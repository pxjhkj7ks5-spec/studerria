async function up(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS telegram_daily_schedule_deliveries (
      id BIGSERIAL PRIMARY KEY,
      delivery_key TEXT NOT NULL UNIQUE,
      mode TEXT NOT NULL CHECK (mode IN ('automatic', 'manual')),
      target_date DATE NOT NULL,
      chat_id TEXT NOT NULL,
      thread_id BIGINT,
      course_id INTEGER NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('sending', 'sent', 'failed', 'uncertain')),
      message_id BIGINT,
      error TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

module.exports = { id: '067_telegram_daily_schedule_deliveries', up };
