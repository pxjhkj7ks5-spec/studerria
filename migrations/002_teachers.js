const ddl = [
  'ALTER TABLE courses ADD COLUMN IF NOT EXISTS is_teacher_course BOOLEAN NOT NULL DEFAULT FALSE',
  'ALTER TABLE subjects ADD COLUMN IF NOT EXISTS is_general BOOLEAN NOT NULL DEFAULT TRUE',
  `
    CREATE TABLE IF NOT EXISTS teacher_requests (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS teacher_subjects (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      group_number INTEGER,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, subject_id, group_number)
    )
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '002_teachers',
  up,
};
