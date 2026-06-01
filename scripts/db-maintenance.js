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
    'Usage: node scripts/db-maintenance.js [--apply] [--mode analyze|vacuum] [--table <name>] [--json] [--help]',
    '',
    'Build or run safe Postgres table maintenance for Studerria hot tables.',
    'Default mode is dry-run and prints statements without executing them.',
    '',
    'Options:',
    '  --apply         Execute generated statements.',
    '  --mode <mode>   analyze (default) or vacuum.',
    '  --table <name>  Limit to one known hot table.',
    '  --json          Print machine-readable JSON.',
    '  --help          Show this help.',
  ].join('\n'));
}

function parseArgs(argv) {
  const options = {
    apply: false,
    json: false,
    help: false,
    mode: 'analyze',
    table: '',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--apply') {
      options.apply = true;
    } else if (arg === '--json') {
      options.json = true;
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--mode') {
      const value = String(argv[index + 1] || '').trim().toLowerCase();
      if (!value || value.startsWith('--')) throw new UsageError('--mode requires analyze or vacuum.');
      if (!['analyze', 'vacuum'].includes(value)) throw new UsageError('--mode must be analyze or vacuum.');
      options.mode = value;
      index += 1;
    } else if (arg === '--table') {
      const value = String(argv[index + 1] || '').trim();
      if (!value || value.startsWith('--')) throw new UsageError('--table requires a table name.');
      if (!dbPerformance.MAINTENANCE_TABLES.includes(value)) {
        throw new UsageError(`Unknown table "${value}". Expected one of: ${dbPerformance.MAINTENANCE_TABLES.join(', ')}`);
      }
      options.table = value;
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

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    printHelp();
    return;
  }
  const requestedTables = options.table ? [options.table] : dbPerformance.MAINTENANCE_TABLES;
  const statements = dbPerformance.buildMaintenanceStatements(requestedTables, { mode: options.mode });
  const result = {
    generated_at: new Date().toISOString(),
    mode: options.mode,
    applied: options.apply,
    statements: [],
  };
  if (!options.apply) {
    result.statements = statements.map((statement, index) => ({ table: requestedTables[index], statement, skipped: false }));
    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log('DB maintenance dry-run');
      result.statements.forEach((item) => console.log(`${item.statement};`));
    }
    return;
  }

  const pool = createPool();
  try {
    for (let index = 0; index < requestedTables.length; index += 1) {
      const table = requestedTables[index];
      const statement = statements[index];
      if (!(await tableExists(pool, table))) {
        result.statements.push({ table, statement, skipped: true, reason: 'missing_table' });
        continue;
      }
      const startedAt = Date.now();
      await pool.query(statement);
      result.statements.push({ table, statement, skipped: false, duration_ms: Date.now() - startedAt });
    }
  } finally {
    await pool.end();
  }
  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`DB maintenance applied (${options.mode})`);
    result.statements.forEach((item) => {
      console.log(`${item.table}: ${item.skipped ? `skipped (${item.reason})` : `${item.duration_ms}ms`}`);
    });
  }
}

main().catch((err) => {
  if (err && err.name === 'UsageError') {
    console.error(`db-maintenance usage error: ${err.message}`);
    printHelp();
    process.exit(2);
  }
  console.error(`db-maintenance failed: ${err && err.message ? err.message : err}`);
  process.exit(1);
});
