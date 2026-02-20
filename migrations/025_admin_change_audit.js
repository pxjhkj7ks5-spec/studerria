const ddl = [
  `
    CREATE TABLE IF NOT EXISTS admin_change_audit (
      id SERIAL PRIMARY KEY,
      scope_key TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_key TEXT,
      summary TEXT,
      before_state JSONB,
      after_state JSONB,
      operation_id TEXT,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_by_name TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      is_rolled_back BOOLEAN NOT NULL DEFAULT false,
      rolled_back_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      rolled_back_at TIMESTAMPTZ,
      CHECK (scope_key IN ('system_settings', 'role_studio'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS admin_change_audit_scope_course_idx
    ON admin_change_audit (scope_key, course_id, created_at DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS admin_change_audit_target_idx
    ON admin_change_audit (scope_key, target_type, target_key, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS admin_change_audit_rollback_idx
    ON admin_change_audit (scope_key, is_rolled_back, created_at DESC)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '025_admin_change_audit',
  up,
};
