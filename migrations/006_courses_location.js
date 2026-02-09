const ddl = [
  "ALTER TABLE courses ADD COLUMN IF NOT EXISTS location TEXT NOT NULL DEFAULT 'kyiv'",
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '006_courses_location',
  up,
};
