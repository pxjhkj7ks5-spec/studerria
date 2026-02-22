const ddl = [
  `
    ALTER TABLE competency_evaluations
    ADD COLUMN IF NOT EXISTS source_ref TEXT
  `,
  `
    DO $$
    DECLARE
      constraint_name TEXT;
    BEGIN
      FOR constraint_name IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
        WHERE t.relname = 'competency_evaluations'
          AND c.contype = 'c'
          AND a.attname = 'source_type'
      LOOP
        EXECUTE format('ALTER TABLE competency_evaluations DROP CONSTRAINT IF EXISTS %I', constraint_name);
      END LOOP;
    END
    $$;
  `,
  `
    ALTER TABLE competency_evaluations
    DROP CONSTRAINT IF EXISTS competency_evaluations_source_type_check
  `,
  `
    ALTER TABLE competency_evaluations
    ADD CONSTRAINT competency_evaluations_source_type_check
    CHECK (source_type IN ('manual', 'column', 'checklist', 'auto_homework_on_time'))
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS competency_evaluations_auto_source_ref_uidx
    ON competency_evaluations (student_id, subject_id, competency_key, source_type, source_ref)
    WHERE source_type = 'auto_homework_on_time' AND source_ref IS NOT NULL
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '030_competency_auto_sources',
  up,
};
