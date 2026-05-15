const ddl = [
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS team_join_open INTEGER NOT NULL DEFAULT 1',
  'UPDATE teamwork_tasks SET team_join_open = 1 WHERE team_join_open IS NULL',
  'CREATE INDEX IF NOT EXISTS idx_teamwork_tasks_join_open ON teamwork_tasks (team_join_open)',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '058_teamwork_join_open_state',
  up,
};
