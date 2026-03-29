const ddl = [
  'ALTER TABLE academic_v2_groups ADD COLUMN IF NOT EXISTS is_teacher_registration_default BOOLEAN NOT NULL DEFAULT FALSE',
];

async function up(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const statement of ddl) {
      await client.query(statement);
    }
    await client.query(
      `
        UPDATE academic_v2_groups group_item
        SET is_teacher_registration_default = FALSE
        WHERE is_teacher_registration_default IS NULL
      `
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  id: '044_academic_v2_teacher_registration_defaults',
  up,
};
