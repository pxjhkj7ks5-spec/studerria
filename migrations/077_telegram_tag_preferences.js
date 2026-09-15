async function up(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS telegram_tag_preferences (
      telegram_id TEXT PRIMARY KEY CHECK (telegram_id ~ '^[1-9][0-9]*$'),
      tag_enabled BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

module.exports = { id: '077_telegram_tag_preferences', up };
