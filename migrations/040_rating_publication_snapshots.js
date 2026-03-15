const ddl = [
  `
    CREATE TABLE IF NOT EXISTS rating_publication_snapshots (
      id SERIAL PRIMARY KEY,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      subject_id INTEGER REFERENCES subjects(id) ON DELETE SET NULL,
      group_number INTEGER,
      scope_type TEXT NOT NULL DEFAULT 'subject',
      scope_label TEXT NOT NULL,
      period TEXT NOT NULL DEFAULT 'semester',
      period_label TEXT,
      compare_mode TEXT NOT NULL DEFAULT 'none',
      target_kind TEXT NOT NULL DEFAULT 'course',
      top_n INTEGER NOT NULL DEFAULT 10,
      summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      ranking_json JSONB NOT NULL DEFAULT '[]'::jsonb,
      message_id INTEGER REFERENCES messages(id) ON DELETE SET NULL,
      published_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      published_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS rating_publication_snapshots_scope_idx
    ON rating_publication_snapshots (course_id, semester_id, published_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS rating_publication_snapshots_subject_idx
    ON rating_publication_snapshots (subject_id, group_number, published_at DESC)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '040_rating_publication_snapshots',
  up,
};
