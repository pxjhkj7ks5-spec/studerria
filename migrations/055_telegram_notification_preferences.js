const ddl = [
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS telegram_notifications_enabled BOOLEAN NOT NULL DEFAULT true',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '055_telegram_notification_preferences',
  up,
};
