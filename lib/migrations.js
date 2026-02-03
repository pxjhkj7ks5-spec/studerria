const migrations = require('../migrations');

async function runMigrations(pool) {
  await pool.query(
    `
      CREATE TABLE IF NOT EXISTS migrations (
        id TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `
  );

  const appliedRows = await pool.query('SELECT id FROM migrations');
  const applied = new Set(appliedRows.rows.map((row) => row.id));

  for (const migration of migrations) {
    if (applied.has(migration.id)) continue;
    await pool.query('BEGIN');
    try {
      await migration.up(pool);
      await pool.query('INSERT INTO migrations (id) VALUES ($1)', [migration.id]);
      await pool.query('COMMIT');
    } catch (err) {
      await pool.query('ROLLBACK');
      throw err;
    }
  }
}

module.exports = {
  runMigrations,
};
