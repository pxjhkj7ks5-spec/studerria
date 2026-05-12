const ddl = [
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_id TEXT',
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_username TEXT',
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_first_name TEXT',
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_last_name TEXT',
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_photo_url TEXT',
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_linked_at TIMESTAMPTZ',
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_last_seen_at TIMESTAMPTZ',
  'CREATE UNIQUE INDEX IF NOT EXISTS users_telegram_id_unique_idx ON users (telegram_id) WHERE telegram_id IS NOT NULL',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '054_telegram_mini_app_users',
  up,
};
