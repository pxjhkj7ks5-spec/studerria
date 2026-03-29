const ddl = [
  `
    CREATE TABLE IF NOT EXISTS academic_v2_group_subject_activities (
      id SERIAL PRIMARY KEY,
      group_subject_id INTEGER NOT NULL REFERENCES academic_v2_group_subjects(id) ON DELETE CASCADE,
      activity_type TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(group_subject_id, activity_type),
      CHECK (activity_type IN ('lecture', 'seminar', 'practice', 'lab'))
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_program_stage_subject_activities (
      id SERIAL PRIMARY KEY,
      stage_subject_template_id INTEGER NOT NULL REFERENCES academic_v2_program_stage_subject_templates(id) ON DELETE CASCADE,
      activity_type TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(stage_subject_template_id, activity_type),
      CHECK (activity_type IN ('lecture', 'seminar', 'practice', 'lab'))
    )
  `,
  `
    ALTER TABLE academic_v2_schedule_entries
    ADD COLUMN IF NOT EXISTS group_subject_activity_id INTEGER REFERENCES academic_v2_group_subject_activities(id) ON DELETE CASCADE
  `,
  `
    ALTER TABLE academic_v2_schedule_entries
    ADD COLUMN IF NOT EXISTS target_group_numbers INTEGER[] NOT NULL DEFAULT ARRAY[1]::INTEGER[]
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_schedule_entry_legacy_links (
      id SERIAL PRIMARY KEY,
      schedule_entry_id INTEGER NOT NULL REFERENCES academic_v2_schedule_entries(id) ON DELETE CASCADE,
      group_number INTEGER NOT NULL,
      legacy_schedule_entry_id INTEGER NOT NULL UNIQUE REFERENCES schedule_entries(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(schedule_entry_id, group_number)
    )
  `,
  'CREATE INDEX IF NOT EXISTS academic_v2_group_subject_activities_subject_idx ON academic_v2_group_subject_activities (group_subject_id, sort_order, id)',
  'CREATE INDEX IF NOT EXISTS academic_v2_stage_subject_activities_subject_idx ON academic_v2_program_stage_subject_activities (stage_subject_template_id, sort_order, id)',
  'CREATE INDEX IF NOT EXISTS academic_v2_schedule_entries_activity_idx ON academic_v2_schedule_entries (group_subject_activity_id, term_id, day_of_week, class_number)',
  'CREATE INDEX IF NOT EXISTS academic_v2_schedule_links_schedule_idx ON academic_v2_schedule_entry_legacy_links (schedule_entry_id, group_number)',
];

const backfillSql = [
  `
    INSERT INTO academic_v2_group_subject_activities
      (group_subject_id, activity_type, sort_order, created_at, updated_at)
    SELECT DISTINCT
      se.group_subject_id,
      CASE LOWER(TRIM(COALESCE(se.lesson_type, '')))
        WHEN 'seminar' THEN 'seminar'
        WHEN 'practice' THEN 'practice'
        WHEN 'lab' THEN 'lab'
        ELSE 'lecture'
      END AS activity_type,
      CASE LOWER(TRIM(COALESCE(se.lesson_type, '')))
        WHEN 'lecture' THEN 10
        WHEN 'seminar' THEN 20
        WHEN 'practice' THEN 30
        WHEN 'lab' THEN 40
        ELSE 10
      END AS sort_order,
      NOW(),
      NOW()
    FROM academic_v2_schedule_entries se
    WHERE NOT EXISTS (
      SELECT 1
      FROM academic_v2_group_subject_activities activity
      WHERE activity.group_subject_id = se.group_subject_id
        AND activity.activity_type = CASE LOWER(TRIM(COALESCE(se.lesson_type, '')))
          WHEN 'seminar' THEN 'seminar'
          WHEN 'practice' THEN 'practice'
          WHEN 'lab' THEN 'lab'
          ELSE 'lecture'
        END
    )
  `,
  `
    UPDATE academic_v2_schedule_entries se
    SET
      group_subject_activity_id = activity.id,
      target_group_numbers = CASE
        WHEN activity.activity_type = 'lecture' THEN ARRAY[]::INTEGER[]
        ELSE ARRAY[GREATEST(1, COALESCE(se.group_number, 1))]::INTEGER[]
      END,
      lesson_type = activity.activity_type,
      group_number = CASE
        WHEN activity.activity_type = 'lecture' THEN 1
        ELSE GREATEST(1, COALESCE(se.group_number, 1))
      END,
      updated_at = NOW()
    FROM academic_v2_group_subject_activities activity
    WHERE activity.group_subject_id = se.group_subject_id
      AND activity.activity_type = CASE LOWER(TRIM(COALESCE(se.lesson_type, '')))
        WHEN 'seminar' THEN 'seminar'
        WHEN 'practice' THEN 'practice'
        WHEN 'lab' THEN 'lab'
        ELSE 'lecture'
      END
      AND se.group_subject_activity_id IS NULL
  `,
  `
    INSERT INTO academic_v2_schedule_entry_legacy_links
      (schedule_entry_id, group_number, legacy_schedule_entry_id, created_at, updated_at)
    SELECT
      se.id,
      CASE
        WHEN COALESCE(activity.activity_type, 'lecture') = 'lecture' THEN 1
        ELSE GREATEST(1, COALESCE(se.group_number, 1))
      END AS group_number,
      se.legacy_schedule_entry_id,
      NOW(),
      NOW()
    FROM academic_v2_schedule_entries se
    LEFT JOIN academic_v2_group_subject_activities activity ON activity.id = se.group_subject_activity_id
    WHERE se.legacy_schedule_entry_id IS NOT NULL
    ON CONFLICT (schedule_entry_id, group_number)
    DO UPDATE SET
      legacy_schedule_entry_id = EXCLUDED.legacy_schedule_entry_id,
      updated_at = NOW()
  `,
  `
    UPDATE academic_v2_schedule_entries
    SET target_group_numbers = ARRAY[]::INTEGER[]
    WHERE lesson_type = 'lecture'
  `,
  `
    UPDATE academic_v2_schedule_entries
    SET target_group_numbers = ARRAY[GREATEST(1, COALESCE(group_number, 1))]::INTEGER[]
    WHERE lesson_type <> 'lecture'
      AND COALESCE(array_length(target_group_numbers, 1), 0) = 0
  `,
  `
    ALTER TABLE academic_v2_schedule_entries
    ALTER COLUMN group_subject_activity_id SET NOT NULL
  `,
  `
    DO $$
    DECLARE constraint_name TEXT;
    BEGIN
      SELECT conname
      INTO constraint_name
      FROM pg_constraint
      WHERE conrelid = 'academic_v2_schedule_entries'::regclass
        AND contype = 'u'
        AND pg_get_constraintdef(oid) LIKE 'UNIQUE (group_subject_id, term_id, group_number, day_of_week, class_number, week_number, lesson_type)%'
      LIMIT 1;

      IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE academic_v2_schedule_entries DROP CONSTRAINT %I', constraint_name);
      END IF;
    END $$;
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS academic_v2_schedule_entries_activity_slot_key
      ON academic_v2_schedule_entries (
        group_subject_activity_id,
        term_id,
        day_of_week,
        class_number,
        week_number,
        target_group_numbers
      )
  `,
];

async function up(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const statement of ddl) {
      await client.query(statement);
    }
    for (const statement of backfillSql) {
      await client.query(statement);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  id: '045_academic_v2_subject_activities',
  up,
};
