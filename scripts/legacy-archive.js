#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const securityHelpers = require('../lib/security');

const repoRoot = path.resolve(__dirname, '..');

function readFlagValue(flagName) {
  const args = process.argv.slice(2);
  const exact = args.find((arg) => arg.startsWith(`${flagName}=`));
  if (exact) return exact.slice(flagName.length + 1).trim();
  const index = args.indexOf(flagName);
  if (index >= 0 && args[index + 1] && !String(args[index + 1]).startsWith('--')) {
    return String(args[index + 1]).trim();
  }
  return '';
}

function parseLimit() {
  const raw = Number(readFlagValue('--limit') || 20);
  return Number.isInteger(raw) && raw > 0 ? Math.min(raw, 200) : 20;
}

function buildDefaultArchivePath() {
  const now = new Date();
  const stamp = [
    now.getUTCFullYear(),
    String(now.getUTCMonth() + 1).padStart(2, '0'),
    String(now.getUTCDate()).padStart(2, '0'),
    '-',
    String(now.getUTCHours()).padStart(2, '0'),
    String(now.getUTCMinutes()).padStart(2, '0'),
    String(now.getUTCSeconds()).padStart(2, '0'),
  ].join('');
  return path.join(repoRoot, 'artifacts', `legacy-archive-${stamp}.json`);
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

async function tableExists(client, tableName) {
  const result = await client.query(
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

async function getCount(client, tableName) {
  const result = await client.query(`SELECT COUNT(*)::int AS count FROM ${tableName}`);
  return Number(result.rows && result.rows[0] && result.rows[0].count || 0);
}

async function getSample(client, tableName, limit) {
  const result = await client.query(`SELECT * FROM ${tableName} ORDER BY 1 ASC LIMIT $1`, [limit]);
  return result.rows || [];
}

async function collectLegacyReport(client, limit) {
  const candidateTables = [
    'courses',
    'study_programs',
    'program_admissions',
    'study_contexts',
    'study_context_semesters',
    'subjects',
    'teacher_subjects',
    'schedule_entries',
    'semesters',
    'academic_v2_groups',
    'academic_v2_terms',
    'academic_v2_group_subjects',
    'academic_v2_schedule_entries',
  ];
  const tables = [];
  for (const tableName of candidateTables) {
    if (!(await tableExists(client, tableName))) {
      tables.push({ table: tableName, exists: false, count: 0, sample: [] });
      continue;
    }
    tables.push({
      table: tableName,
      exists: true,
      count: await getCount(client, tableName),
      sample: await getSample(client, tableName, limit),
    });
  }
  return {
    generatedAt: new Date().toISOString(),
    mode: 'archive-export',
    destructiveChanges: false,
    limit,
    tables,
    migrationGate: {
      canDropLegacySchemaNow: false,
      requiredBeforeDrop: [
        'Store this archive artifact outside the container/worktree backup path.',
        'Verify login, registration, schedule, Academic Setup, and teacher workspace on production-like data.',
        'Add a separate migration with an explicit rollback note.',
      ],
    },
  };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--drop') || args.includes('--delete') || args.includes('--apply-drop')) {
    throw new Error('Destructive legacy drops are intentionally blocked in this script. Create a separate reviewed migration after archive verification.');
  }

  const dryRun = args.includes('--dry-run') || !args.includes('--archive');
  const limit = parseLimit();
  const pool = createPool();
  try {
    let client;
    try {
      client = await pool.connect();
    } catch (err) {
      if (dryRun) {
        console.log(JSON.stringify({
          generatedAt: new Date().toISOString(),
          mode: 'dry-run',
          destructiveChanges: false,
          databaseAvailable: false,
          error: err && err.message ? err.message : String(err),
          nextSteps: [
            'Start the Docker database or provide DB_HOST, DB_PORT, DB_USER, DB_PASS, and DB_NAME.',
            'Re-run node scripts/legacy-archive.js --dry-run to collect row counts.',
            'Use --archive only after the dry-run report is available.',
          ],
        }, null, 2));
        return;
      }
      throw err;
    }
    try {
      const report = await collectLegacyReport(client, limit);
      report.databaseAvailable = true;
      report.mode = dryRun ? 'dry-run' : 'archive-export';
      if (!dryRun) {
        const outPath = readFlagValue('--out') || buildDefaultArchivePath();
        fs.mkdirSync(path.dirname(outPath), { recursive: true });
        fs.writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
        report.archivePath = outPath;
      }
      console.log(JSON.stringify(report, null, 2));
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error('legacy-archive failed');
  console.error(err && err.stack ? err.stack : err);
  process.exitCode = 1;
});
