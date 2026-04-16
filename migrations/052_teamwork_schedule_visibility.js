const ddl = [
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS show_in_schedule INTEGER NOT NULL DEFAULT 0',
  'CREATE INDEX IF NOT EXISTS idx_teamwork_tasks_schedule_deadline ON teamwork_tasks (show_in_schedule, due_date)',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '052_teamwork_schedule_visibility',
  up,
};
