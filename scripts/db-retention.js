#!/usr/bin/env node

const { Pool } = require('pg');
const securityHelpers = require('../lib/security');
const dbPerformance = require('../lib/dbPerformance');

class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
  }
}

function printHelp() {
  console.log([
    'Usage: node scripts/db-retention.js [--apply] [--table <name>] [--days <n>] [--json] [--help]',
    '',
    'Estimate or apply retention cleanup for large Studerria log tables.',
    'Default mode is dry-run and only counts rows that would be removed.',
    '',
    'Options:',
    '  --apply         Execute DELETE statements.',
    '  --table <name>  Limit to one retention target.',
    '  --days <n>      Override retention days for selected targets.',
    '  --json          Print machine-readable JSON.',
    '  --help          Show this help.',
  ].join('\n'));
}

function parsePositiveInt(rawValue, fallback = 0) {
  const value = Number(rawValue);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

function parseArgs(argv) {
  const options = {
    apply: false,
    json: false,
    help: false,
    table: '',
    days: 0,
  };
  const targetNames = dbPerformance.RETENTION_TARGETS.map((target) => target.table);
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--apply') {
      options.apply = true;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--table') {
      const value = String(argv[index + 1] || '').trim();
      if (!value || value.startsWith('--')) throw new UsageError('--table requires a table name.');
      if (!targetNames.includes(value)) {
        throw new UsageError(`Unknown table "${value}". Expected one of: ${targetNames.join(', ')}`);
      }
      options.table = value;
      index += 1;
    } else if (arg === '--days') {
      const value = parsePositiveInt(argv[index + 1]);
      if (!value) throw new UsageError('--days requires a positive integer.');
      options.days = value;
      index += 1;
    } else {
      throw new UsageError(`Unknown option: ${arg}`);
    }
  }
  return options;
}

function createPool() {
  const dbSslEnabled = String(process.env.DB_SSL || '').trim().toLowerCase() === 'true';
  return new Pool({
    host: process.env.DB_HOST || (process.env.INSTANCE_CONNECTION_NAME ? `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}` : 'localhost'),
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
    ssl: securityHelpers.resolveDbSslConfig({
      enabled: dbSslEnabled,
      ca: process.env.DB_SSL_CA || '',
    }),
  });
}

async function tableExists(pool, tableName) {
  const result = await pool.query(
    `
      SELECT EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = $1
      ) AS exists
    `,
    [tableName]
  );
  return Boolean(result.rows && result.rows[0] && result.rows[0].exists);
}

function buildCountSql(deleteSql = '') {
  return String(deleteSql || '').replace(/^DELETE FROM\s+(.+?)\s+WHERE\s+/i, 'SELECT COUNT(*)::int AS count FROM $1 WHERE ');
}

function buildApplySql(deleteSql = '') {
  return `WITH deleted AS (${deleteSql} RETURNING 1) SELECT COUNT(*)::int AS count FROM deleted`;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    printHelp();
    return;
  }
  const targets = dbPerformance.RETENTION_TARGETS
    .filter((target) => !options.table || target.table === options.table);
  const pool = createPool();
  const result = {
    generated_at: new Date().toISOString(),
    applied: options.apply,
    targets: [],
  };
  try {
    for (const target of targets) {
      const days = options.days || target.defaultDays;
      const plan = dbPerformance.buildRetentionDeleteSql(target, days);
      if (!(await tableExists(pool, target.table))) {
        result.targets.push({ table: target.table, days, skipped: true, reason: 'missing_table' });
        continue;
      }
      const sql = options.apply ? buildApplySql(plan.sql) : buildCountSql(plan.sql);
      const startedAt = Date.now();
      const queryResult = await pool.query(sql, [days]);
      result.targets.push({
        table: target.table,
        days,
        deleted: options.apply ? Number(queryResult.rows && queryResult.rows[0] && queryResult.rows[0].count || 0) : 0,
        would_delete: options.apply ? undefined : Number(queryResult.rows && queryResult.rows[0] && queryResult.rows[0].count || 0),
        skipped: false,
        duration_ms: Date.now() - startedAt,
      });
    }
  } finally {
    await pool.end();
  }
  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(options.apply ? 'DB retention applied' : 'DB retention dry-run');
    result.targets.forEach((target) => {
      if (target.skipped) {
        console.log(`${target.table}: skipped (${target.reason})`);
      } else if (options.apply) {
        console.log(`${target.table}: deleted=${target.deleted}, days=${target.days}`);
      } else {
        console.log(`${target.table}: would_delete=${target.would_delete}, days=${target.days}`);
      }
    });
  }
}

main().catch((err) => {
  if (err && err.name === 'UsageError') {
    console.error(`db-retention usage error: ${err.message}`);
    printHelp();
    process.exit(2);
  }
  console.error(`db-retention failed: ${err && err.message ? err.message : err}`);
  process.exit(1);
});
