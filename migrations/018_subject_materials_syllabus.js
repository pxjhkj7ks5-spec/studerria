const ddl = [
  'ALTER TABLE subject_materials ADD COLUMN IF NOT EXISTS is_syllabus INTEGER NOT NULL DEFAULT 0',
  'UPDATE subject_materials SET is_syllabus = 0 WHERE is_syllabus IS NULL',
  `
    CREATE INDEX IF NOT EXISTS subject_materials_syllabus_idx
    ON subject_materials (subject_id, is_syllabus, created_at DESC)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '018_subject_materials_syllabus',
  up,
};
