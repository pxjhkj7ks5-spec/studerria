async function up(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS telegram_daily_schedule_bindings (
      id BIGSERIAL PRIMARY KEY,
      academic_group_id INTEGER NOT NULL REFERENCES academic_v2_groups(id) ON DELETE RESTRICT,
      chat_id TEXT NOT NULL CHECK (chat_id ~ '^-?[1-9][0-9]*$'),
      thread_id BIGINT CHECK (thread_id IS NULL OR thread_id > 0),
      is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS telegram_daily_schedule_bindings_destination_uidx
    ON telegram_daily_schedule_bindings (chat_id, COALESCE(thread_id, 0))
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS telegram_daily_schedule_bindings_group_idx
    ON telegram_daily_schedule_bindings (academic_group_id, is_enabled)
  `);
  await pool.query(`
    ALTER TABLE telegram_daily_schedule_deliveries
    ADD COLUMN IF NOT EXISTS binding_id BIGINT
      REFERENCES telegram_daily_schedule_bindings(id) ON DELETE SET NULL
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS telegram_daily_schedule_deliveries_binding_idx
    ON telegram_daily_schedule_deliveries (binding_id, created_at DESC)
  `);
  await pool.query(`
    INSERT INTO access_permissions (key, label, category)
    VALUES ('admin-tg-schedule', 'Розсилка розкладу', 'admin_section')
    ON CONFLICT (key) DO UPDATE
    SET label = EXCLUDED.label,
        category = EXCLUDED.category
  `);
  await pool.query(`
    INSERT INTO access_role_permissions (role_id, permission_id, allowed, created_at, updated_at)
    SELECT role.id, permission.id, TRUE, NOW(), NOW()
    FROM access_roles role
    JOIN access_permissions permission ON permission.key = 'admin-tg-schedule'
    WHERE role.key = 'admin'
    ON CONFLICT (role_id, permission_id) DO UPDATE
    SET allowed = TRUE,
        updated_at = NOW()
  `);
}

module.exports = { id: '076_telegram_daily_schedule_bindings', up };
