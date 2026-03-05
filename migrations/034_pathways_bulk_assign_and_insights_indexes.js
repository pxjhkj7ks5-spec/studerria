const ddl = [
  `
    CREATE INDEX IF NOT EXISTS subjects_course_normalized_name_idx
    ON subjects (course_id, LOWER(TRIM(name)))
  `,
  `
    CREATE INDEX IF NOT EXISTS program_admission_courses_course_admission_idx
    ON program_admission_courses (course_id, admission_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS subject_visibility_by_admission_subject_admission_idx
    ON subject_visibility_by_admission (subject_id, admission_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS subject_visibility_by_admission_admission_visible_idx
    ON subject_visibility_by_admission (admission_id, is_visible)
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_grades_column_student_graded_idx
    ON journal_grades (column_id, student_id, graded_at)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '034_pathways_bulk_assign_and_insights_indexes',
  up,
};
