const ddl = [
  'ALTER TABLE teamwork_groups ADD COLUMN IF NOT EXISTS seminar_group_number INTEGER',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '016_teamwork_groups_seminar_group_number',
  up,
};
