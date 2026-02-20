const ddl = [
  `
    CREATE TABLE IF NOT EXISTS journal_grade_appeals (
      id SERIAL PRIMARY KEY,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      column_id INTEGER NOT NULL REFERENCES journal_columns(id) ON DELETE CASCADE,
      student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      requested_score NUMERIC(6, 2),
      reason TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      decision_comment TEXT,
      resolved_score NUMERIC(6, 2),
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      sla_due_at TIMESTAMPTZ NOT NULL,
      reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      reviewed_at TIMESTAMPTZ,
      CHECK (status IN ('pending', 'in_review', 'approved', 'rejected')),
      CHECK (reason <> '')
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS journal_grade_appeals_single_open_idx
    ON journal_grade_appeals (column_id, student_id)
    WHERE status IN ('pending', 'in_review')
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_grade_appeals_cell_idx
    ON journal_grade_appeals (column_id, student_id, created_at DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_grade_appeals_sla_idx
    ON journal_grade_appeals (status, sla_due_at)
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_grade_appeals_student_idx
    ON journal_grade_appeals (student_id, created_at DESC)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '024_journal_grade_appeals',
  up,
};
