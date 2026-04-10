const ddl = [
  `
    ALTER TABLE admin_change_audit
    ADD COLUMN IF NOT EXISTS actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
  `,
  `
    ALTER TABLE admin_change_audit
    ADD COLUMN IF NOT EXISTS actor_name_snapshot TEXT
  `,
  `
    ALTER TABLE admin_change_audit
    ADD COLUMN IF NOT EXISTS action_type TEXT NOT NULL DEFAULT 'legacy_entry'
  `,
  `
    ALTER TABLE admin_change_audit
    ADD COLUMN IF NOT EXISTS target_id INTEGER
  `,
  `
    ALTER TABLE admin_change_audit
    ADD COLUMN IF NOT EXISTS metadata JSONB
  `,
  `
    ALTER TABLE admin_change_audit
    ADD COLUMN IF NOT EXISTS is_critical BOOLEAN NOT NULL DEFAULT false
  `,
  `
    ALTER TABLE admin_change_audit
    ADD COLUMN IF NOT EXISTS rollback_source_audit_id INTEGER REFERENCES admin_change_audit(id) ON DELETE SET NULL
  `,
  `
    ALTER TABLE admin_change_audit
    ADD COLUMN IF NOT EXISTS previous_hash TEXT
  `,
  `
    ALTER TABLE admin_change_audit
    ADD COLUMN IF NOT EXISTS current_hash TEXT
  `,
  `
    ALTER TABLE admin_change_audit
    ADD COLUMN IF NOT EXISTS hash_version TEXT NOT NULL DEFAULT 'sha256-v1'
  `,
  `
    UPDATE admin_change_audit
    SET actor_user_id = COALESCE(actor_user_id, created_by),
        actor_name_snapshot = COALESCE(NULLIF(actor_name_snapshot, ''), created_by_name),
        action_type = COALESCE(NULLIF(action_type, ''), 'legacy_entry')
  `,
  `
    CREATE INDEX IF NOT EXISTS admin_change_audit_action_idx
    ON admin_change_audit (scope_key, action_type, created_at DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS admin_change_audit_hash_idx
    ON admin_change_audit (created_at DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS admin_change_audit_rollback_source_idx
    ON admin_change_audit (rollback_source_audit_id)
  `,
  `
    ALTER TABLE site_visit_events
    ADD COLUMN IF NOT EXISTS is_frozen BOOLEAN NOT NULL DEFAULT false
  `,
  `
    ALTER TABLE site_visit_events
    ADD COLUMN IF NOT EXISTS hold_until TIMESTAMPTZ
  `,
  `
    ALTER TABLE site_visit_events
    ADD COLUMN IF NOT EXISTS incident_id TEXT
  `,
  `
    ALTER TABLE login_history
    ADD COLUMN IF NOT EXISTS is_frozen BOOLEAN NOT NULL DEFAULT false
  `,
  `
    ALTER TABLE login_history
    ADD COLUMN IF NOT EXISTS hold_until TIMESTAMPTZ
  `,
  `
    ALTER TABLE login_history
    ADD COLUMN IF NOT EXISTS incident_id TEXT
  `,
  `
    ALTER TABLE activity_log
    ADD COLUMN IF NOT EXISTS is_frozen BOOLEAN NOT NULL DEFAULT false
  `,
  `
    ALTER TABLE activity_log
    ADD COLUMN IF NOT EXISTS hold_until TIMESTAMPTZ
  `,
  `
    ALTER TABLE activity_log
    ADD COLUMN IF NOT EXISTS incident_id TEXT
  `,
  `
    ALTER TABLE auth_failure_events
    ADD COLUMN IF NOT EXISTS is_frozen BOOLEAN NOT NULL DEFAULT false
  `,
  `
    ALTER TABLE auth_failure_events
    ADD COLUMN IF NOT EXISTS hold_until TIMESTAMPTZ
  `,
  `
    ALTER TABLE auth_failure_events
    ADD COLUMN IF NOT EXISTS incident_id TEXT
  `,
  `
    ALTER TABLE user_registration_events
    ADD COLUMN IF NOT EXISTS is_frozen BOOLEAN NOT NULL DEFAULT false
  `,
  `
    ALTER TABLE user_registration_events
    ADD COLUMN IF NOT EXISTS hold_until TIMESTAMPTZ
  `,
  `
    ALTER TABLE user_registration_events
    ADD COLUMN IF NOT EXISTS incident_id TEXT
  `,
  `
    ALTER TABLE user_role_change_events
    ADD COLUMN IF NOT EXISTS is_frozen BOOLEAN NOT NULL DEFAULT false
  `,
  `
    ALTER TABLE user_role_change_events
    ADD COLUMN IF NOT EXISTS hold_until TIMESTAMPTZ
  `,
  `
    ALTER TABLE user_role_change_events
    ADD COLUMN IF NOT EXISTS incident_id TEXT
  `,
  `
    ALTER TABLE security_alert_events
    ADD COLUMN IF NOT EXISTS is_frozen BOOLEAN NOT NULL DEFAULT false
  `,
  `
    ALTER TABLE security_alert_events
    ADD COLUMN IF NOT EXISTS hold_until TIMESTAMPTZ
  `,
  `
    ALTER TABLE security_alert_events
    ADD COLUMN IF NOT EXISTS incident_id TEXT
  `,
  `
    CREATE TABLE IF NOT EXISTS security_risk_events (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      session_id TEXT,
      ip TEXT,
      device_fingerprint TEXT,
      geo_key TEXT,
      source_type TEXT NOT NULL,
      action_type TEXT NOT NULL,
      risk_score INTEGER NOT NULL DEFAULT 0,
      risk_level TEXT NOT NULL DEFAULT 'none',
      trust_bonus INTEGER NOT NULL DEFAULT 0,
      allowlisted BOOLEAN NOT NULL DEFAULT false,
      triggered_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
      metadata JSONB,
      alert_status TEXT NOT NULL DEFAULT 'none',
      alert_event_id INTEGER REFERENCES security_alert_events(id) ON DELETE SET NULL,
      quarantine_status TEXT NOT NULL DEFAULT 'none',
      is_frozen BOOLEAN NOT NULL DEFAULT false,
      hold_until TIMESTAMPTZ,
      incident_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (risk_level IN ('none', 'low', 'medium', 'high')),
      CHECK (alert_status IN ('none', 'open', 'deduped')),
      CHECK (quarantine_status IN ('none', 'applied', 'skipped'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS security_risk_events_user_idx
    ON security_risk_events (user_id, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS security_risk_events_actor_idx
    ON security_risk_events (actor_user_id, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS security_risk_events_level_idx
    ON security_risk_events (risk_level, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS security_risk_events_ip_idx
    ON security_risk_events (ip, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS security_risk_events_source_idx
    ON security_risk_events (source_type, action_type, created_at DESC)
  `,
  `
    CREATE TABLE IF NOT EXISTS security_cleanup_runs (
      id BIGSERIAL PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'ok',
      summary JSONB,
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      finished_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (status IN ('ok', 'error'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS security_cleanup_runs_created_idx
    ON security_cleanup_runs (created_at DESC)
  `,
  `
    INSERT INTO settings (key, value)
    VALUES
      ('session_idle_timeout_minutes', '60'),
      ('session_absolute_timeout_hours', '336'),
      ('security_stepup_reauth_minutes', '15'),
      ('security_logs_retention_days', '120'),
      ('security_device_retention_days', '45'),
      ('security_risk_threshold_low', '35'),
      ('security_risk_threshold_medium', '65'),
      ('security_risk_threshold_high', '95')
    ON CONFLICT (key) DO NOTHING
  `,
  `
    INSERT INTO settings (key, value)
    SELECT 'security_device_retention_days', value
    FROM settings
    WHERE key = 'security_user_agent_retention_days'
    ON CONFLICT (key) DO NOTHING
  `,
  `
    CREATE OR REPLACE FUNCTION reject_admin_change_audit_mutation()
    RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'admin_change_audit is append-only';
    END;
    $$ LANGUAGE plpgsql
  `,
  `
    DROP TRIGGER IF EXISTS admin_change_audit_block_mutation
    ON admin_change_audit
  `,
  `
    CREATE TRIGGER admin_change_audit_block_mutation
    BEFORE UPDATE OR DELETE ON admin_change_audit
    FOR EACH ROW
    EXECUTE FUNCTION reject_admin_change_audit_mutation()
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '049_security_hardening_admin_controls',
  up,
};
