const ddl = [
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS show_full_schedule BOOLEAN NOT NULL DEFAULT false',
  `CREATE TABLE IF NOT EXISTS academic_v2_group_day_formats (
    group_id INTEGER NOT NULL REFERENCES academic_v2_groups(id) ON DELETE CASCADE,
    day_of_week TEXT NOT NULL CHECK (day_of_week IN ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')),
    delivery_mode TEXT NOT NULL DEFAULT 'offline' CHECK (delivery_mode IN ('offline', 'online', 'mixed')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, day_of_week)
  )`,
  'CREATE INDEX IF NOT EXISTS academic_v2_group_day_formats_group_idx ON academic_v2_group_day_formats (group_id, day_of_week)',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = { id: '068_studerria_schedule_preferences', up };
