const statements = [
  `
    CREATE TABLE IF NOT EXISTS academic_v2_shared_group_subject_links (
      id SERIAL PRIMARY KEY,
      source_group_subject_id INTEGER NOT NULL REFERENCES academic_v2_group_subjects(id) ON DELETE CASCADE,
      linked_group_subject_id INTEGER NOT NULL UNIQUE REFERENCES academic_v2_group_subjects(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(source_group_subject_id, linked_group_subject_id),
      CHECK (source_group_subject_id <> linked_group_subject_id)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS academic_v2_shared_group_subject_links_source_idx
    ON academic_v2_shared_group_subject_links (source_group_subject_id, linked_group_subject_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS academic_v2_shared_group_subject_links_linked_idx
    ON academic_v2_shared_group_subject_links (linked_group_subject_id, source_group_subject_id)
  `,
];

async function up(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const statement of statements) {
      await client.query(statement);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  id: '047_academic_v2_shared_group_subject_links',
  up,
};
