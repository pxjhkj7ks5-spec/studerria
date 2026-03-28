#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const academicV2Helpers = require('../lib/academicV2');
const securityHelpers = require('../lib/security');

function createStore(pool) {
  const query = async (sql, params = []) => pool.query(sql, params);
  return {
    get: async (sql, params = []) => {
      const result = await query(sql, params);
      return result.rows && result.rows[0] ? result.rows[0] : null;
    },
    all: async (sql, params = []) => {
      const result = await query(sql, params);
      return result.rows || [];
    },
    run: async (sql, params = []) => query(sql, params),
    withTransaction: async (work) => {
      const client = await pool.connect();
      const tx = {
        get: async (sql, params = []) => {
          const result = await client.query(sql, params);
          return result.rows && result.rows[0] ? result.rows[0] : null;
        },
        all: async (sql, params = []) => {
          const result = await client.query(sql, params);
          return result.rows || [];
        },
        run: async (sql, params = []) => client.query(sql, params),
      };
      try {
        await client.query('BEGIN');
        const result = await work(tx);
        await client.query('COMMIT');
        return result;
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
    },
  };
}

function readFlagValue(flagName) {
  const args = process.argv.slice(2);
  const exact = args.find((arg) => arg.startsWith(`${flagName}=`));
  if (exact) {
    return exact.slice(flagName.length + 1).trim();
  }
  const index = args.indexOf(flagName);
  if (index >= 0 && args[index + 1] && !String(args[index + 1]).startsWith('--')) {
    return String(args[index + 1]).trim();
  }
  return '';
}

function buildDefaultSnapshotPath() {
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
  return path.join(process.cwd(), 'artifacts', `academic-v2-audit-${stamp}.json`);
}

async function main() {
  const args = process.argv.slice(2);
  const runResyncAll = process.argv.includes('--resync-all');
  const includeDetails = args.includes('--details');
  const explicitSnapshotPath = readFlagValue('--out');
  const writeSnapshot = args.includes('--write-snapshot') || Boolean(explicitSnapshotPath);
  const detailLimit = (() => {
    const raw = Number(readFlagValue('--limit') || 25);
    return Number.isInteger(raw) && raw > 0 ? Math.min(raw, 200) : 25;
  })();
  const dbSslEnabled = String(process.env.DB_SSL || '').trim().toLowerCase() === 'true';
  const pool = new Pool({
    host: process.env.DB_HOST || `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}`,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
    ssl: securityHelpers.resolveDbSslConfig({
      enabled: dbSslEnabled,
      ca: process.env.DB_SSL_CA || '',
    }),
  });

  const store = createStore(pool);
  try {
    const before = await academicV2Helpers.loadAcademicAuditSnapshot(store);
    const beforeDetails = includeDetails
      ? await academicV2Helpers.loadAcademicCleanupDetails(store, { limit: detailLimit })
      : null;
    if (!runResyncAll) {
      const payload = {
        mode: 'dry-run',
        ...before,
        ...(beforeDetails ? { cleanupDetails: beforeDetails } : {}),
      };
      if (writeSnapshot) {
        const snapshotPath = explicitSnapshotPath || buildDefaultSnapshotPath();
        fs.mkdirSync(path.dirname(snapshotPath), { recursive: true });
        fs.writeFileSync(snapshotPath, JSON.stringify(payload, null, 2) + '\n', 'utf8');
        payload.snapshotPath = snapshotPath;
      }
      console.log(JSON.stringify(payload, null, 2));
      return;
    }

    const resyncResult = await academicV2Helpers.resyncAllGroupProjections(store);
    const after = await academicV2Helpers.loadAcademicAuditSnapshot(store);
    const afterDetails = includeDetails
      ? await academicV2Helpers.loadAcademicCleanupDetails(store, { limit: detailLimit })
      : null;
    const payload = {
      mode: 'resync-all',
      resyncResult,
      before,
      after,
      ...(beforeDetails ? { cleanupDetailsBefore: beforeDetails } : {}),
      ...(afterDetails ? { cleanupDetailsAfter: afterDetails } : {}),
    };
    if (writeSnapshot) {
      const snapshotPath = explicitSnapshotPath || buildDefaultSnapshotPath();
      fs.mkdirSync(path.dirname(snapshotPath), { recursive: true });
      fs.writeFileSync(snapshotPath, JSON.stringify(payload, null, 2) + '\n', 'utf8');
      payload.snapshotPath = snapshotPath;
    }
    console.log(JSON.stringify(payload, null, 2));
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error('academic-v2-audit failed');
  console.error(err && err.stack ? err.stack : err);
  process.exitCode = 1;
});
