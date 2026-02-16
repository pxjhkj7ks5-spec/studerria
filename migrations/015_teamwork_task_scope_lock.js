const ddl = [
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS group_lock_enabled INTEGER NOT NULL DEFAULT 0',
  "ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS lesson_scope TEXT NOT NULL DEFAULT 'lecture'",
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS seminar_group_numbers TEXT',
  "UPDATE teamwork_tasks SET lesson_scope = 'lecture' WHERE lesson_scope IS NULL OR lesson_scope NOT IN ('lecture', 'seminar')",
  'UPDATE teamwork_tasks SET group_lock_enabled = 0 WHERE group_lock_enabled IS NULL',
  "UPDATE teamwork_tasks SET seminar_group_numbers = 'all' WHERE lesson_scope = 'seminar' AND (seminar_group_numbers IS NULL OR seminar_group_numbers = '')",
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '015_teamwork_task_scope_lock',
  up,
};
