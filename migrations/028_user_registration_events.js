const ddl = [
  `
    CREATE TABLE IF NOT EXISTS user_registration_events (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      full_name TEXT NOT NULL,
      ip TEXT,
      user_agent TEXT,
      device_fingerprint TEXT,
      session_id TEXT,
      source TEXT NOT NULL DEFAULT 'register_form',
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (source IN ('register_form', 'import', 'admin_create'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS user_registration_events_user_idx
    ON user_registration_events (user_id, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS user_registration_events_ip_idx
    ON user_registration_events (ip, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS user_registration_events_session_idx
    ON user_registration_events (session_id, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS user_registration_events_fingerprint_idx
    ON user_registration_events (device_fingerprint, created_at DESC)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '028_user_registration_events',
  up,
};
