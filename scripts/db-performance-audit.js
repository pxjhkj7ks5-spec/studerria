#!/usr/bin/env node

const { Pool } = require('pg');
const securityHelpers = require('../lib/security');

const KEY_TABLES = [
  'users',
  'schedule_entries',
  'homework',
  'messages',
  'message_targets',
  'message_reads',
  'teamwork_tasks',
  'teamwork_groups',
  'teamwork_members',
  'site_visit_events',
  'history_log',
];

class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
  }
}

function printHelp() {
  console.log([
    'Usage: node scripts/db-performance-audit.js [--json] [--table <name>] [--help]',
    '',
    'Read-only Postgres performance snapshot for Studerria key tables.',
    '',
    'Options:',
    '  --json          Print machine-readable JSON.',
    '  --table <name>  Limit output to one key table.',
    '  --help          Show this help.',
  ].join('\n'));
}

function parseArgs(argv) {
  const options = {
    json: false,
    table: '',
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--json') {
      options.json = true;
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--table') {
      if (!argv[index + 1] || String(argv[index + 1]).startsWith('--')) {
        throw new UsageError('--table requires a table name.');
      }
      options.table = String(argv[index + 1] || '').trim();
      index += 1;
    } else {
      throw new UsageError(`Unknown option: ${arg}`);
    }
  }
  if (options.table && !KEY_TABLES.includes(options.table)) {
    throw new UsageError(`Unknown table "${options.table}". Expected one of: ${KEY_TABLES.join(', ')}`);
  }
  return options;
}

function resolvePoolConfig() {
  const dbSslEnabled = String(process.env.DB_SSL || '').trim().toLowerCase() === 'true';
  return {
    host: process.env.DB_HOST || `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
    ssl: securityHelpers.resolveDbSslConfig({
      enabled: dbSslEnabled,
      ca: process.env.DB_SSL_CA || '',
    }),
  };
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function buildTableNote(table) {
  const seqScans = Number(table.seq_scan || 0);
  const indexScans = Number(table.idx_scan || 0);
  const liveRows = Number(table.n_live_tup || 0);
  const deadRows = Number(table.n_dead_tup || 0);
  const notes = [];
  if (liveRows > 1000 && seqScans > indexScans * 2) {
    notes.push('seq-scan-heavy');
  }
  if (deadRows > Math.max(1000, liveRows * 0.2)) {
    notes.push('dead-tuples-high');
  }
  if (!table.indexes || table.indexes.length === 0) {
    notes.push('no-visible-indexes');
  }
  return notes;
}

async function loadAudit(pool, options) {
  const tableNames = options.table ? [options.table] : KEY_TABLES;
  const statsResult = await pool.query(
    `
      SELECT
        relname,
        seq_scan,
        seq_tup_read,
        idx_scan,
        idx_tup_fetch,
        n_live_tup,
        n_dead_tup,
        vacuum_count,
        autovacuum_count,
        analyze_count,
        autoanalyze_count,
        pg_total_relation_size(relid) AS total_bytes,
        pg_relation_size(relid) AS table_bytes
      FROM pg_stat_user_tables
      WHERE relname = ANY($1::text[])
      ORDER BY relname ASC
    `,
    [tableNames],
  );
  const indexesResult = await pool.query(
    `
      SELECT
        tablename,
        indexname,
        indexdef
      FROM pg_indexes
      WHERE schemaname = 'public'
        AND tablename = ANY($1::text[])
      ORDER BY tablename ASC, indexname ASC
    `,
    [tableNames],
  );
  const indexStatsResult = await pool.query(
    `
      SELECT
        relname AS tablename,
        indexrelname AS indexname,
        idx_scan,
        idx_tup_read,
        idx_tup_fetch,
        pg_relation_size(indexrelid) AS index_bytes
      FROM pg_stat_user_indexes
      WHERE relname = ANY($1::text[])
      ORDER BY relname ASC, indexrelname ASC
    `,
    [tableNames],
  );

  const indexStatsByKey = new Map();
  for (const row of indexStatsResult.rows || []) {
    indexStatsByKey.set(`${row.tablename}|${row.indexname}`, {
      idx_scan: Number(row.idx_scan || 0),
      idx_tup_read: Number(row.idx_tup_read || 0),
      idx_tup_fetch: Number(row.idx_tup_fetch || 0),
      index_bytes: Number(row.index_bytes || 0),
    });
  }
  const indexesByTable = new Map();
  for (const row of indexesResult.rows || []) {
    if (!indexesByTable.has(row.tablename)) {
      indexesByTable.set(row.tablename, []);
    }
    const stats = indexStatsByKey.get(`${row.tablename}|${row.indexname}`) || {};
    indexesByTable.get(row.tablename).push({
      name: row.indexname,
      definition: row.indexdef,
      idx_scan: Number(stats.idx_scan || 0),
      idx_tup_read: Number(stats.idx_tup_read || 0),
      idx_tup_fetch: Number(stats.idx_tup_fetch || 0),
      index_bytes: Number(stats.index_bytes || 0),
    });
  }

  const statsByTable = new Map((statsResult.rows || []).map((row) => [row.relname, row]));
  return {
    generated_at: new Date().toISOString(),
    tables: tableNames.map((tableName) => {
      const row = statsByTable.get(tableName) || { relname: tableName };
      const table = {
        name: tableName,
        total_bytes: Number(row.total_bytes || 0),
        table_bytes: Number(row.table_bytes || 0),
        seq_scan: Number(row.seq_scan || 0),
        seq_tup_read: Number(row.seq_tup_read || 0),
        idx_scan: Number(row.idx_scan || 0),
        idx_tup_fetch: Number(row.idx_tup_fetch || 0),
        n_live_tup: Number(row.n_live_tup || 0),
        n_dead_tup: Number(row.n_dead_tup || 0),
        vacuum_count: Number(row.vacuum_count || 0),
        autovacuum_count: Number(row.autovacuum_count || 0),
        analyze_count: Number(row.analyze_count || 0),
        autoanalyze_count: Number(row.autoanalyze_count || 0),
        indexes: indexesByTable.get(tableName) || [],
      };
      table.notes = buildTableNote(table);
      return table;
    }),
  };
}

function printText(audit) {
  console.log(`DB performance audit (${audit.generated_at})`);
  for (const table of audit.tables) {
    const notes = table.notes.length ? ` | notes: ${table.notes.join(', ')}` : '';
    console.log('');
    console.log(`${table.name}: ${formatBytes(table.total_bytes)} total, rows=${table.n_live_tup}, dead=${table.n_dead_tup}${notes}`);
    console.log(`  scans: seq=${table.seq_scan} (${table.seq_tup_read} rows read), index=${table.idx_scan} (${table.idx_tup_fetch} rows fetched)`);
    console.log(`  maintenance: vacuum=${table.vacuum_count}/${table.autovacuum_count}, analyze=${table.analyze_count}/${table.autoanalyze_count}`);
    if (!table.indexes.length) {
      console.log('  indexes: none visible');
      continue;
    }
    console.log('  indexes:');
    for (const index of table.indexes) {
      console.log(`    - ${index.name} (${formatBytes(index.index_bytes)}, scans=${index.idx_scan})`);
    }
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    printHelp();
    return;
  }
  const pool = new Pool(resolvePoolConfig());
  try {
    const audit = await loadAudit(pool, options);
    if (options.json) {
      console.log(JSON.stringify(audit, null, 2));
    } else {
      printText(audit);
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  if (err && err.name === 'UsageError') {
    console.error(`DB performance audit usage error: ${err.message}`);
    printHelp();
    process.exit(2);
  }
  console.error(`DB performance audit failed: ${err && err.message ? err.message : err}`);
  process.exit(1);
});
