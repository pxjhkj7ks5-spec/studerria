const ddl = [
  `
    ALTER TABLE journal_grades
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ
  `,
  `
    ALTER TABLE journal_grades
    ADD COLUMN IF NOT EXISTS deleted_by INTEGER REFERENCES users(id) ON DELETE SET NULL
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_grades_active_lookup_idx
    ON journal_grades (column_id, student_id, deleted_at)
  `,
  `
    ALTER TABLE journal_columns
    ADD COLUMN IF NOT EXISTS is_locked INTEGER NOT NULL DEFAULT 0
  `,
  `
    ALTER TABLE journal_columns
    ADD COLUMN IF NOT EXISTS locked_by INTEGER REFERENCES users(id) ON DELETE SET NULL
  `,
  `
    ALTER TABLE journal_columns
    ADD COLUMN IF NOT EXISTS locked_at TIMESTAMPTZ
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_columns_subject_lock_idx
    ON journal_columns (subject_id, course_id, is_locked, is_archived, position, id)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '021_journal_grade_undo_and_lock',
  up,
};
