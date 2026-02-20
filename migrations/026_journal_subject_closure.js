const ddl = [
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS is_closed BOOLEAN NOT NULL DEFAULT false
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS closed_by INTEGER REFERENCES users(id) ON DELETE SET NULL
  `,
  `
    ALTER TABLE subject_grading_settings
    ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ
  `,
  `
    CREATE INDEX IF NOT EXISTS subject_grading_settings_closed_idx
    ON subject_grading_settings (course_id, semester_id, is_closed, subject_id)
  `,
  `
    CREATE TABLE IF NOT EXISTS journal_subject_close_events (
      id SERIAL PRIMARY KEY,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      event_type TEXT NOT NULL DEFAULT 'closed',
      export_file_name TEXT,
      export_file_path TEXT,
      export_rows_count INTEGER NOT NULL DEFAULT 0,
      export_columns_count INTEGER NOT NULL DEFAULT 0,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      details JSONB,
      CHECK (event_type IN ('closed'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_subject_close_events_subject_idx
    ON journal_subject_close_events (subject_id, created_at DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS journal_subject_close_events_course_semester_idx
    ON journal_subject_close_events (course_id, semester_id, created_at DESC)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '026_journal_subject_closure',
  up,
};
