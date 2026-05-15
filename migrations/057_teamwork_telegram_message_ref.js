const ddl = [
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS telegram_chat_id TEXT',
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS telegram_message_id INTEGER',
  'CREATE INDEX IF NOT EXISTS idx_teamwork_tasks_telegram_message ON teamwork_tasks (telegram_chat_id, telegram_message_id)',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '057_teamwork_telegram_message_ref',
  up,
};
