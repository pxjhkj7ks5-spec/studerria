const ddl = [
  `
    CREATE TABLE IF NOT EXISTS teacher_homework_templates (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      subject_id INTEGER REFERENCES subjects(id) ON DELETE SET NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      link_url TEXT,
      meeting_url TEXT,
      tags TEXT NOT NULL DEFAULT '',
      is_control BOOLEAN NOT NULL DEFAULT false,
      is_credit BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS teacher_homework_templates_user_updated_idx
    ON teacher_homework_templates (user_id, updated_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS teacher_homework_templates_scope_idx
    ON teacher_homework_templates (user_id, course_id, subject_id)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '033_teacher_homework_templates',
  up,
};
