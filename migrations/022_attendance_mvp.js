const ddl = [
  `
    CREATE TABLE IF NOT EXISTS attendance_records (
      id SERIAL PRIMARY KEY,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      group_number INTEGER,
      class_date DATE NOT NULL,
      class_number INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'present',
      reason TEXT,
      marked_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      marked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (class_number >= 1 AND class_number <= 7),
      CHECK (status IN ('present', 'late', 'absent', 'excused'))
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS attendance_records_slot_unique_semester_idx
    ON attendance_records (subject_id, course_id, semester_id, class_date, class_number, student_id)
    WHERE semester_id IS NOT NULL
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS attendance_records_slot_unique_no_semester_idx
    ON attendance_records (subject_id, course_id, class_date, class_number, student_id)
    WHERE semester_id IS NULL
  `,
  `
    CREATE INDEX IF NOT EXISTS attendance_records_subject_slot_idx
    ON attendance_records (subject_id, course_id, class_date, class_number)
  `,
  `
    CREATE INDEX IF NOT EXISTS attendance_records_student_idx
    ON attendance_records (student_id, subject_id, class_date DESC)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '022_attendance_mvp',
  up,
};
