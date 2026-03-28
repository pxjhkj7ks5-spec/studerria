#!/usr/bin/env node

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

async function main() {
  const runResyncAll = process.argv.includes('--resync-all');
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
    if (!runResyncAll) {
      console.log(JSON.stringify({
        mode: 'dry-run',
        ...before,
      }, null, 2));
      return;
    }

    const resyncResult = await academicV2Helpers.resyncAllGroupProjections(store);
    const after = await academicV2Helpers.loadAcademicAuditSnapshot(store);
    console.log(JSON.stringify({
      mode: 'resync-all',
      resyncResult,
      before,
      after,
    }, null, 2));
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error('academic-v2-audit failed');
  console.error(err && err.stack ? err.stack : err);
  process.exitCode = 1;
});
