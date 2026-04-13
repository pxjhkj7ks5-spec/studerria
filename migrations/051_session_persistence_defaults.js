const ddl = [
  `
    INSERT INTO settings (key, value)
    VALUES
      ('session_idle_timeout_minutes', '20160'),
      ('session_absolute_timeout_hours', '672'),
      ('session_duration_days', '28')
    ON CONFLICT (key) DO NOTHING
  `,
  `
    UPDATE settings
    SET value = '20160'
    WHERE key = 'session_idle_timeout_minutes'
      AND CASE
        WHEN NULLIF(TRIM(value), '') IS NULL THEN true
        WHEN TRIM(value) ~ '^[0-9]+$' THEN TRIM(value)::INTEGER < 20160
        ELSE true
      END
  `,
  `
    UPDATE settings
    SET value = '672'
    WHERE key = 'session_absolute_timeout_hours'
      AND CASE
        WHEN NULLIF(TRIM(value), '') IS NULL THEN true
        WHEN TRIM(value) ~ '^[0-9]+$' THEN TRIM(value)::INTEGER < 672
        ELSE true
      END
  `,
  `
    UPDATE settings AS duration
    SET value = (
      SELECT GREATEST(
        28,
        CASE
          WHEN NULLIF(TRIM(abs.value), '') IS NULL THEN 28
          WHEN TRIM(abs.value) ~ '^[0-9]+$' THEN CEIL(TRIM(abs.value)::NUMERIC / 24.0)::INTEGER
          ELSE 28
        END
      )::TEXT
      FROM settings AS abs
      WHERE abs.key = 'session_absolute_timeout_hours'
    )
    WHERE duration.key = 'session_duration_days'
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '051_session_persistence_defaults',
  up,
};
