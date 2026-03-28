const ddl = [
  'ALTER TABLE academic_v2_cohorts ADD COLUMN IF NOT EXISTS current_stage_number INTEGER NOT NULL DEFAULT 1',
  `
    CREATE TABLE IF NOT EXISTS academic_v2_program_stage_templates (
      id SERIAL PRIMARY KEY,
      program_id INTEGER NOT NULL REFERENCES academic_v2_programs(id) ON DELETE CASCADE,
      stage_number INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(program_id, stage_number)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_program_stage_term_templates (
      id SERIAL PRIMARY KEY,
      stage_template_id INTEGER NOT NULL REFERENCES academic_v2_program_stage_templates(id) ON DELETE CASCADE,
      term_number INTEGER NOT NULL,
      title TEXT NOT NULL,
      start_date TEXT,
      weeks_count INTEGER NOT NULL DEFAULT 16,
      is_active_default BOOLEAN NOT NULL DEFAULT FALSE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(stage_template_id, term_number)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_program_stage_subject_templates (
      id SERIAL PRIMARY KEY,
      stage_template_id INTEGER NOT NULL REFERENCES academic_v2_program_stage_templates(id) ON DELETE CASCADE,
      subject_template_id INTEGER NOT NULL REFERENCES academic_v2_subject_templates(id) ON DELETE CASCADE,
      title TEXT,
      group_count INTEGER NOT NULL DEFAULT 1,
      default_group INTEGER NOT NULL DEFAULT 1,
      is_visible BOOLEAN NOT NULL DEFAULT TRUE,
      is_required BOOLEAN NOT NULL DEFAULT TRUE,
      is_general BOOLEAN NOT NULL DEFAULT TRUE,
      show_in_teamwork BOOLEAN NOT NULL DEFAULT TRUE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(stage_template_id, subject_template_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_program_stage_subject_terms (
      stage_subject_template_id INTEGER NOT NULL REFERENCES academic_v2_program_stage_subject_templates(id) ON DELETE CASCADE,
      stage_term_template_id INTEGER NOT NULL REFERENCES academic_v2_program_stage_term_templates(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(stage_subject_template_id, stage_term_template_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_program_stage_subject_teachers (
      stage_subject_template_id INTEGER NOT NULL REFERENCES academic_v2_program_stage_subject_templates(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      is_primary BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(stage_subject_template_id, user_id)
    )
  `,
  'CREATE INDEX IF NOT EXISTS academic_v2_program_stage_templates_program_idx ON academic_v2_program_stage_templates (program_id, stage_number)',
  'CREATE INDEX IF NOT EXISTS academic_v2_program_stage_term_templates_stage_idx ON academic_v2_program_stage_term_templates (stage_template_id, term_number)',
  'CREATE INDEX IF NOT EXISTS academic_v2_program_stage_subject_templates_stage_idx ON academic_v2_program_stage_subject_templates (stage_template_id, sort_order, id)',
];

async function up(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const statement of ddl) {
      await client.query(statement);
    }
    await client.query(
      `
        UPDATE academic_v2_cohorts cohort
        SET current_stage_number = COALESCE((
          SELECT MIN(group_item.stage_number)
          FROM academic_v2_groups group_item
          WHERE group_item.cohort_id = cohort.id
            AND COALESCE(group_item.is_active, TRUE) = TRUE
        ), (
          SELECT MIN(group_item.stage_number)
          FROM academic_v2_groups group_item
          WHERE group_item.cohort_id = cohort.id
        ), 1)
      `
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  id: '043_academic_v2_stage_templates',
  up,
};
