const ddl = [
  `
    ALTER TABLE journal_columns
    ADD COLUMN IF NOT EXISTS include_in_final INTEGER NOT NULL DEFAULT 1
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS homework_enabled INTEGER NOT NULL DEFAULT 1
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS seminar_enabled INTEGER NOT NULL DEFAULT 1
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS exam_enabled INTEGER NOT NULL DEFAULT 1
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS credit_enabled INTEGER NOT NULL DEFAULT 1
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS custom_enabled INTEGER NOT NULL DEFAULT 1
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS homework_weight_points NUMERIC(6, 2) NOT NULL DEFAULT 20
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS seminar_weight_points NUMERIC(6, 2) NOT NULL DEFAULT 20
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS exam_weight_points NUMERIC(6, 2) NOT NULL DEFAULT 40
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS credit_weight_points NUMERIC(6, 2) NOT NULL DEFAULT 10
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS custom_weight_points NUMERIC(6, 2) NOT NULL DEFAULT 10
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_columns_subject_include_idx
    ON journal_columns (subject_id, course_id, include_in_final, is_archived, position, id)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '020_journal_weighted_config',
  up,
};
