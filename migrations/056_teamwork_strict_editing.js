const ddl = [
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS strict_team_editing INTEGER NOT NULL DEFAULT 0',
  'CREATE INDEX IF NOT EXISTS idx_teamwork_tasks_strict_editing ON teamwork_tasks (strict_team_editing)',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '056_teamwork_strict_editing',
  up,
};
