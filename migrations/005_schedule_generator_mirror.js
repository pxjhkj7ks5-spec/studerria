const ddl = [
  "ALTER TABLE schedule_generator_items ADD COLUMN IF NOT EXISTS mirror_key TEXT",
  "ALTER TABLE schedule_generator_entries ADD COLUMN IF NOT EXISTS is_mirror BOOLEAN NOT NULL DEFAULT FALSE",
  "ALTER TABLE schedule_generator_entries ADD COLUMN IF NOT EXISTS mirror_key TEXT",
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '005_schedule_generator_mirror',
  up,
};
