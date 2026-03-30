const statements = [
  `
    INSERT INTO academic_v2_program_stage_subject_activities
      (stage_subject_template_id, activity_type, sort_order, created_at, updated_at)
    SELECT
      stage_subject.id,
      'lecture',
      10,
      NOW(),
      NOW()
    FROM academic_v2_program_stage_subject_templates stage_subject
    WHERE NOT EXISTS (
      SELECT 1
      FROM academic_v2_program_stage_subject_activities activity
      WHERE activity.stage_subject_template_id = stage_subject.id
    )
  `,
  `
    INSERT INTO academic_v2_group_subject_activities
      (group_subject_id, activity_type, sort_order, created_at, updated_at)
    SELECT
      group_subject.id,
      'lecture',
      10,
      NOW(),
      NOW()
    FROM academic_v2_group_subjects group_subject
    WHERE NOT EXISTS (
      SELECT 1
      FROM academic_v2_group_subject_activities activity
      WHERE activity.group_subject_id = group_subject.id
    )
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
  id: '046_academic_v2_activity_baselines',
  up,
};
