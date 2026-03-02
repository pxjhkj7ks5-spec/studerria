const ddl = [
  `
    CREATE TABLE IF NOT EXISTS session_generator_drafts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      location TEXT NOT NULL DEFAULT 'kyiv',
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      form_json TEXT NOT NULL DEFAULT '{}',
      assignments_json TEXT NOT NULL DEFAULT '[]',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS session_generator_drafts_user_updated_idx
    ON session_generator_drafts (user_id, updated_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS session_generator_drafts_scope_idx
    ON session_generator_drafts (user_id, location, course_id, semester_id)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '031_session_generator_drafts',
  up,
};
