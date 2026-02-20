const ddl = [
  `
    CREATE TABLE IF NOT EXISTS journal_retake_attempts (
      id SERIAL PRIMARY KEY,
      column_id INTEGER NOT NULL REFERENCES journal_columns(id) ON DELETE CASCADE,
      student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      attempt_no INTEGER NOT NULL DEFAULT 1,
      kind TEXT NOT NULL DEFAULT 'retake',
      status TEXT NOT NULL DEFAULT 'planned',
      due_date DATE,
      approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      approved_at TIMESTAMPTZ,
      note TEXT,
      score NUMERIC(6, 2),
      teacher_comment TEXT,
      graded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      graded_at TIMESTAMPTZ,
      count_in_final INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(column_id, student_id, attempt_no),
      CHECK (attempt_no >= 1),
      CHECK (kind IN ('retake', 'makeup')),
      CHECK (status IN ('planned', 'submitted', 'graded', 'cancelled')),
      CHECK (count_in_final IN (0, 1))
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS journal_retake_attempts_single_final_idx
    ON journal_retake_attempts (column_id, student_id)
    WHERE count_in_final = 1
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_retake_attempts_column_student_idx
    ON journal_retake_attempts (column_id, student_id, attempt_no DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_retake_attempts_due_status_idx
    ON journal_retake_attempts (due_date, status, column_id)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '023_journal_retake_attempts',
  up,
};
