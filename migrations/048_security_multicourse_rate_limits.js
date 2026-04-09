const statements = [
  `
    ALTER TABLE access_roles
    ADD COLUMN IF NOT EXISTS multicourse_enabled BOOLEAN NOT NULL DEFAULT false
  `,
  `
    UPDATE access_roles
    SET multicourse_enabled = true,
        updated_at = NOW()
    WHERE key = 'admin'
  `,
  `
    UPDATE access_roles
    SET multicourse_enabled = false,
        updated_at = NOW()
    WHERE is_system = true
      AND key <> 'admin'
  `,
  `
    CREATE TABLE IF NOT EXISTS rate_limit_counters (
      namespace TEXT NOT NULL,
      subject TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0 CHECK (count >= 0),
      reset_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (namespace, subject)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS rate_limit_counters_reset_at_idx
    ON rate_limit_counters (reset_at)
  `,
];

async function up(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const statement of statements) {
      await client.query(statement);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  id: '048_security_multicourse_rate_limits',
  up,
};
