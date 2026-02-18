const ddl = [
  `
    ALTER TABLE homework
    ADD COLUMN IF NOT EXISTS is_teacher_homework INTEGER NOT NULL DEFAULT 0
  `,
  `
    ALTER TABLE homework
    ADD COLUMN IF NOT EXISTS is_credit INTEGER NOT NULL DEFAULT 0
  `,
  `
    CREATE TABLE IF NOT EXISTS homework_submissions (
      id SERIAL PRIMARY KEY,
      homework_id INTEGER NOT NULL REFERENCES homework(id) ON DELETE CASCADE,
      student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      submission_text TEXT,
      link_url TEXT,
      file_path TEXT,
      file_name TEXT,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(homework_id, student_id)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS homework_submissions_homework_student_idx
    ON homework_submissions (homework_id, student_id)
  `,
  `
    CREATE TABLE IF NOT EXISTS subject_grading_settings (
      id SERIAL PRIMARY KEY,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      homework_max_points NUMERIC(6, 2) NOT NULL DEFAULT 10,
      seminar_max_points NUMERIC(6, 2) NOT NULL DEFAULT 10,
      exam_max_points NUMERIC(6, 2) NOT NULL DEFAULT 40,
      credit_max_points NUMERIC(6, 2) NOT NULL DEFAULT 20,
      custom_max_points NUMERIC(6, 2) NOT NULL DEFAULT 10,
      final_max_points NUMERIC(6, 2) NOT NULL DEFAULT 100,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(subject_id),
      CHECK (homework_max_points > 0),
      CHECK (seminar_max_points > 0),
      CHECK (exam_max_points > 0),
      CHECK (credit_max_points > 0),
      CHECK (custom_max_points > 0),
      CHECK (final_max_points = 100)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS journal_columns (
      id SERIAL PRIMARY KEY,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      source_type TEXT NOT NULL DEFAULT 'manual',
      source_homework_id INTEGER REFERENCES homework(id) ON DELETE SET NULL,
      title TEXT NOT NULL,
      column_type TEXT NOT NULL DEFAULT 'custom',
      max_points NUMERIC(6, 2) NOT NULL DEFAULT 10,
      position INTEGER NOT NULL DEFAULT 0,
      is_credit INTEGER NOT NULL DEFAULT 0,
      is_archived INTEGER NOT NULL DEFAULT 0,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (source_type IN ('manual', 'homework')),
      CHECK (column_type IN ('homework', 'seminar', 'exam', 'credit', 'custom')),
      UNIQUE(source_homework_id)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_columns_subject_semester_idx
    ON journal_columns (subject_id, course_id, semester_id, is_credit, position, id)
  `,
  `
    CREATE TABLE IF NOT EXISTS journal_grades (
      id SERIAL PRIMARY KEY,
      column_id INTEGER NOT NULL REFERENCES journal_columns(id) ON DELETE CASCADE,
      student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      score NUMERIC(6, 2) NOT NULL,
      teacher_comment TEXT,
      graded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      graded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      submission_status TEXT NOT NULL DEFAULT 'missing',
      UNIQUE(column_id, student_id),
      CHECK (submission_status IN ('missing', 'on_time', 'late', 'manual'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_grades_column_student_idx
    ON journal_grades (column_id, student_id)
  `,
  `
    UPDATE homework h
    SET is_teacher_homework = 1
    FROM users u
    WHERE u.id = h.created_by_id
      AND LOWER(COALESCE(u.role, '')) = 'teacher'
      AND COALESCE(h.is_teacher_homework, 0) = 0
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '019_journal_gradebook',
  up,
};
