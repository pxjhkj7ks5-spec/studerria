'use strict';

const { Pool } = require('pg');
const migrations = require('./migrations');

function createPool(config) {
  return new Pool({
    connectionString: config.databaseUrl,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });
}

async function migrate(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS osint_schema_migrations (
      id TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  for (const migration of migrations) {
    const existing = await pool.query('SELECT 1 FROM osint_schema_migrations WHERE id = $1', [migration.id]);
    if (existing.rowCount) continue;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await migration.up(client);
      await client.query('INSERT INTO osint_schema_migrations (id) VALUES ($1)', [migration.id]);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}

module.exports = { createPool, migrate };
