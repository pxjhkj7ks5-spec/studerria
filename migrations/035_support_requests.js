const ddl = [
  `
    CREATE TABLE IF NOT EXISTS support_requests (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      category TEXT NOT NULL DEFAULT 'other',
      subject TEXT NOT NULL,
      body TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'new',
      admin_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      resolved_at TIMESTAMPTZ,
      resolved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      CHECK (category IN ('account', 'schedule', 'journal', 'subjects', 'teamwork', 'other')),
      CHECK (status IN ('new', 'in_progress', 'resolved'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS support_requests_user_idx
    ON support_requests (user_id, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS support_requests_course_status_idx
    ON support_requests (course_id, status, updated_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS support_requests_updated_idx
    ON support_requests (updated_at DESC)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '035_support_requests',
  up,
};
