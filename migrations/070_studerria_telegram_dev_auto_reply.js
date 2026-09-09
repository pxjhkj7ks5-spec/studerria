async function up(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS studerria_telegram_dev_auto_reply (
      id SMALLINT PRIMARY KEY CHECK (id = 1),
      enabled BOOLEAN NOT NULL DEFAULT false,
      target_telegram_id TEXT,
      target_username TEXT,
      reply_text TEXT NOT NULL,
      updated_by_telegram_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (target_telegram_id IS NOT NULL OR target_username IS NOT NULL),
      CHECK (CHAR_LENGTH(reply_text) BETWEEN 1 AND 1000)
    )
  `);
}

module.exports = { id: '070_studerria_telegram_dev_auto_reply', up };
