const ddl = [
  `
    CREATE TABLE IF NOT EXISTS auth_failure_events (
      id SERIAL PRIMARY KEY,
      attempted_full_name TEXT,
      normalized_full_name TEXT,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      ip TEXT,
      user_agent TEXT,
      session_id TEXT,
      source TEXT NOT NULL DEFAULT 'login',
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (source IN ('login'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS auth_failure_events_user_idx
    ON auth_failure_events (user_id, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS auth_failure_events_name_idx
    ON auth_failure_events (normalized_full_name, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS auth_failure_events_ip_idx
    ON auth_failure_events (ip, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS auth_failure_events_session_idx
    ON auth_failure_events (session_id, created_at DESC)
  `,
  `
    CREATE TABLE IF NOT EXISTS user_role_change_events (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      target_full_name TEXT,
      actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      actor_name TEXT,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      source TEXT NOT NULL DEFAULT 'admin_users_roles',
      before_roles JSONB NOT NULL DEFAULT '[]'::jsonb,
      after_roles JSONB NOT NULL DEFAULT '[]'::jsonb,
      before_primary_role TEXT,
      after_primary_role TEXT,
      reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (source IN ('admin_users_roles', 'admin_users_role', 'teacher_request_approve', 'teacher_request_reject'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS user_role_change_events_user_idx
    ON user_role_change_events (user_id, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS user_role_change_events_actor_idx
    ON user_role_change_events (actor_user_id, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS user_role_change_events_course_idx
    ON user_role_change_events (course_id, created_at DESC)
  `,
  `
    CREATE TABLE IF NOT EXISTS user_security_cases (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      risk_score INTEGER NOT NULL DEFAULT 0,
      risk_level TEXT NOT NULL DEFAULT 'normal',
      status TEXT NOT NULL DEFAULT 'open',
      reason TEXT,
      reason_details JSONB,
      signal_counters JSONB,
      auto_quarantined BOOLEAN NOT NULL DEFAULT false,
      allowlisted BOOLEAN NOT NULL DEFAULT false,
      last_risk_at TIMESTAMPTZ,
      last_recomputed_at TIMESTAMPTZ,
      confirmed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      confirmed_at TIMESTAMPTZ,
      closed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      closed_at TIMESTAMPTZ,
      resolution_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (risk_level IN ('normal', 'watch', 'high-risk')),
      CHECK (status IN ('open', 'confirmed', 'closed'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS user_security_cases_level_idx
    ON user_security_cases (risk_level, status, updated_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS user_security_cases_status_idx
    ON user_security_cases (status, updated_at DESC)
  `,
  `
    CREATE TABLE IF NOT EXISTS security_alert_events (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      alert_key TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'medium',
      title TEXT NOT NULL,
      message TEXT,
      details JSONB,
      dedup_key TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      resolved_at TIMESTAMPTZ,
      resolved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      CHECK (severity IN ('low', 'medium', 'high', 'critical'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS security_alert_events_created_idx
    ON security_alert_events (created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS security_alert_events_severity_idx
    ON security_alert_events (severity, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS security_alert_events_key_idx
    ON security_alert_events (alert_key, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS security_alert_events_user_idx
    ON security_alert_events (user_id, created_at DESC)
  `,
  `
    CREATE TABLE IF NOT EXISTS journal_grade_hash_audit (
      id SERIAL PRIMARY KEY,
      column_id INTEGER NOT NULL REFERENCES journal_columns(id) ON DELETE CASCADE,
      student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      subject_id INTEGER REFERENCES subjects(id) ON DELETE SET NULL,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      action_type TEXT NOT NULL,
      before_state JSONB,
      after_state JSONB,
      previous_hash TEXT,
      entry_hash TEXT NOT NULL,
      note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_grade_hash_audit_cell_idx
    ON journal_grade_hash_audit (column_id, student_id, created_at DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_grade_hash_audit_created_idx
    ON journal_grade_hash_audit (created_at DESC)
  `,
  `
    INSERT INTO settings (key, value)
    VALUES
      ('security_auto_quarantine_enabled', 'true'),
      ('security_ip_retention_days', '180'),
      ('security_user_agent_retention_days', '120')
    ON CONFLICT (key) DO NOTHING
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '029_security_risk_audit',
  up,
};
