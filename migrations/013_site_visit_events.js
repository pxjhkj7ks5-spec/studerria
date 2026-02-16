const ddl = [
  `
    CREATE TABLE IF NOT EXISTS site_visit_events (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      role_key TEXT,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      route_path TEXT NOT NULL,
      page_key TEXT NOT NULL,
      session_id TEXT,
      ip TEXT,
      user_agent TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  'CREATE INDEX IF NOT EXISTS site_visit_events_created_at_idx ON site_visit_events(created_at DESC)',
  'CREATE INDEX IF NOT EXISTS site_visit_events_course_created_idx ON site_visit_events(course_id, created_at DESC)',
  'CREATE INDEX IF NOT EXISTS site_visit_events_page_idx ON site_visit_events(page_key)',
  'CREATE INDEX IF NOT EXISTS site_visit_events_user_idx ON site_visit_events(user_id)',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '013_site_visit_events',
  up,
};
