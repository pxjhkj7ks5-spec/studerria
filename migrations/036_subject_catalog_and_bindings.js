const ddl = [
  `
    CREATE TABLE IF NOT EXISTS subject_catalog (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      normalized_name TEXT NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  `
    ALTER TABLE subjects
    ADD COLUMN IF NOT EXISTS catalog_id INTEGER REFERENCES subject_catalog(id) ON DELETE SET NULL
  `,
  `
    ALTER TABLE subjects
    ADD COLUMN IF NOT EXISTS is_shared BOOLEAN NOT NULL DEFAULT FALSE
  `,
  `
    CREATE TABLE IF NOT EXISTS subject_course_bindings (
      id SERIAL PRIMARY KEY,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(subject_id, course_id)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS subject_course_bindings_course_idx
    ON subject_course_bindings (course_id, subject_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS subject_course_bindings_subject_idx
    ON subject_course_bindings (subject_id, course_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS subjects_catalog_idx
    ON subjects (catalog_id)
  `,
  `
    DO $$
    BEGIN
      ALTER TABLE subjects DROP CONSTRAINT IF EXISTS subjects_name_key;
    EXCEPTION
      WHEN undefined_table THEN NULL;
    END
    $$
  `,
];

function normalizeCatalogName(value) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }

  const subjects = await pool.query(
    `
      SELECT id, name, course_id
      FROM subjects
      ORDER BY id ASC
    `
  );

  for (const row of subjects.rows || []) {
    const subjectId = Number(row.id || 0);
    const courseId = Number(row.course_id || 0);
    const name = String(row.name || '').replace(/\s+/g, ' ').trim();
    const normalizedName = normalizeCatalogName(name);
    if (!subjectId || !normalizedName) {
      continue;
    }

    const catalogRow = await pool.query(
      `
        INSERT INTO subject_catalog (name, normalized_name, created_at, updated_at)
        VALUES ($1, $2, NOW(), NOW())
        ON CONFLICT (normalized_name)
        DO UPDATE SET
          name = EXCLUDED.name,
          updated_at = NOW()
        RETURNING id
      `,
      [name, normalizedName]
    );
    const catalogId = Number(catalogRow.rows && catalogRow.rows[0] ? catalogRow.rows[0].id : 0);
    if (catalogId > 0) {
      await pool.query(
        'UPDATE subjects SET catalog_id = $1 WHERE id = $2',
        [catalogId, subjectId]
      );
    }
    if (courseId > 0) {
      await pool.query(
        `
          INSERT INTO subject_course_bindings (subject_id, course_id, created_at, updated_at)
          VALUES ($1, $2, NOW(), NOW())
          ON CONFLICT (subject_id, course_id)
          DO UPDATE SET updated_at = NOW()
        `,
        [subjectId, courseId]
      );
    }
  }
}

module.exports = {
  id: '036_subject_catalog_and_bindings',
  up,
};
