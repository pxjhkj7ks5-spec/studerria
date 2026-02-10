const ddl = [
  'ALTER TABLE schedule_entries ADD COLUMN IF NOT EXISTS lesson_type TEXT',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '009_schedule_entry_lesson_type',
  up,
};
