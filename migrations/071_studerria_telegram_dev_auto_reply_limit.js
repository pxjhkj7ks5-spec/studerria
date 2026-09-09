const ddl = [
  `ALTER TABLE studerria_telegram_dev_auto_reply
   ADD COLUMN IF NOT EXISTS reply_limit INTEGER CHECK (reply_limit BETWEEN 1 AND 10000)`,
  `ALTER TABLE studerria_telegram_dev_auto_reply
   ADD COLUMN IF NOT EXISTS replies_sent INTEGER NOT NULL DEFAULT 0 CHECK (replies_sent >= 0)`,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = { id: '071_studerria_telegram_dev_auto_reply_limit', up };
