const ddl = [
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS team_join_closed_by INTEGER REFERENCES users(id) ON DELETE SET NULL',
  'CREATE INDEX IF NOT EXISTS idx_teamwork_tasks_join_closed_by ON teamwork_tasks (team_join_closed_by)',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '059_teamwork_join_closed_by',
  up,
};
