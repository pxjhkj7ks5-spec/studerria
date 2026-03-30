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

function parsePositiveInt(value) {
  const normalized = Number(value || 0);
  return Number.isInteger(normalized) && normalized > 0 ? normalized : null;
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
  return path.join(process.cwd(), 'artifacts', `academic-v2-cleanup-${stamp}.json`);
}

async function main() {
  const args = process.argv.slice(2);
  const applyChanges = args.includes('--apply');
  const runResyncAll = args.includes('--resync-all');
  const runActivityIntegrity = args.includes('--activity-integrity');
  const explicitActions = args.includes('--normalize-users') || args.includes('--archive-legacy-config');
  const runNormalizeUsers = explicitActions ? args.includes('--normalize-users') : true;
  const runArchiveLegacyConfig = explicitActions ? args.includes('--archive-legacy-config') : true;
  const explicitSnapshotPath = readFlagValue('--out');
  const writeSnapshot = args.includes('--write-snapshot') || Boolean(explicitSnapshotPath);
  const limit = (() => {
    const raw = Number(readFlagValue('--limit') || 100);
    return Number.isInteger(raw) && raw > 0 ? Math.min(raw, 500) : 100;
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
    const payload = {
      mode: applyChanges ? 'apply' : 'dry-run',
      requestedActions: {
        resyncAll: runResyncAll,
        activityIntegrity: runActivityIntegrity,
        normalizeUsers: runNormalizeUsers,
        archiveLegacyConfig: runArchiveLegacyConfig,
      },
      limit,
    };

    if (runResyncAll) {
      payload.resyncAllResult = await academicV2Helpers.resyncAllGroupProjections(store);
    }
    if (runActivityIntegrity) {
      payload.activityIntegrityResult = await academicV2Helpers.loadActivityIntegrityReport(store, {
        programId: parsePositiveInt(readFlagValue('--program-id')),
        templateStageNumber: parsePositiveInt(readFlagValue('--template-stage')),
        groupId: parsePositiveInt(readFlagValue('--group-id')),
      });
    }
    if (runNormalizeUsers) {
      payload.normalizeUsersResult = await academicV2Helpers.normalizeUsersIntoAcademicV2Groups(store, {
        apply: applyChanges,
        limit,
      });
    }
    if (runArchiveLegacyConfig) {
      payload.archiveLegacyConfigResult = await academicV2Helpers.archiveStaleLegacyAcademicConfig(store, {
        apply: applyChanges,
        limit,
      });
    }
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
  console.error('academic-v2-cleanup failed');
  console.error(err && err.stack ? err.stack : err);
  process.exitCode = 1;
});
