const ddl = [
  `
    CREATE TABLE IF NOT EXISTS subject_materials (
      id SERIAL PRIMARY KEY,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      group_number INTEGER,
      title TEXT NOT NULL,
      description TEXT,
      material_type TEXT NOT NULL DEFAULT 'lecture',
      link_url TEXT,
      file_path TEXT,
      file_name TEXT,
      created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      course_id INTEGER REFERENCES courses(id),
      semester_id INTEGER REFERENCES semesters(id),
      CHECK (material_type IN ('lecture', 'file', 'link', 'mixed'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS subject_materials_subject_idx
    ON subject_materials (subject_id, course_id, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS subject_materials_group_idx
    ON subject_materials (subject_id, group_number)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '017_subject_materials',
  up,
};
