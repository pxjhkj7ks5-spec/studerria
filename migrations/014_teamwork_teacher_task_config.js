const ddl = [
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS random_distribution INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS group_count INTEGER NOT NULL DEFAULT 1',
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS member_limits_enabled INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS min_members INTEGER',
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS max_members INTEGER',
  'UPDATE teamwork_tasks SET group_count = 1 WHERE group_count IS NULL OR group_count < 1',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '014_teamwork_teacher_task_config',
  up,
};
