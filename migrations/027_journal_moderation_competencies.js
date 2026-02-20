const ddl = [
  `
    CREATE TABLE IF NOT EXISTS journal_grade_moderations (
      id SERIAL PRIMARY KEY,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      column_id INTEGER NOT NULL REFERENCES journal_columns(id) ON DELETE CASCADE,
      student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'pending',
      original_score NUMERIC(6, 2),
      moderated_score NUMERIC(6, 2),
      moderation_comment TEXT,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      reviewed_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(column_id, student_id),
      CHECK (status IN ('pending', 'approved', 'adjusted', 'rejected'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_grade_moderations_subject_idx
    ON journal_grade_moderations (subject_id, status, updated_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_grade_moderations_course_semester_idx
    ON journal_grade_moderations (course_id, semester_id, status, updated_at DESC)
  `,
  `
    CREATE TABLE IF NOT EXISTS competency_evaluations (
      id SERIAL PRIMARY KEY,
      course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      column_id INTEGER REFERENCES journal_columns(id) ON DELETE SET NULL,
      student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      competency_key TEXT NOT NULL,
      score NUMERIC(6, 2) NOT NULL,
      note TEXT,
      source_type TEXT NOT NULL DEFAULT 'manual',
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (score >= 0 AND score <= 5),
      CHECK (source_type IN ('manual', 'column'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS competency_evaluations_student_idx
    ON competency_evaluations (student_id, competency_key, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS competency_evaluations_course_semester_idx
    ON competency_evaluations (course_id, semester_id, subject_id, competency_key, created_at DESC)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '027_journal_moderation_competencies',
  up,
};
