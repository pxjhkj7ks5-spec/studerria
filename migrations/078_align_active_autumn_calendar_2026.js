'use strict';

const AUTUMN_START_DATE = '2026-08-31';
const STALE_BEFORE_DATE = '2026-06-01';

async function tableExists(pool, tableName) {
  const result = await pool.query('SELECT to_regclass($1) AS relation', [`public.${tableName}`]);
  return Boolean(result.rows && result.rows[0] && result.rows[0].relation);
}

async function up(pool) {
  if (await tableExists(pool, 'academic_v2_program_stage_term_templates')) {
    await pool.query(`
      UPDATE academic_v2_program_stage_term_templates
      SET start_date = $1,
          updated_at = NOW()
      WHERE term_number = 1
        AND is_active_default = TRUE
        AND (start_date IS NULL OR start_date < $2)
    `, [AUTUMN_START_DATE, STALE_BEFORE_DATE]);
  }

  if (await tableExists(pool, 'academic_v2_terms')) {
    await pool.query(`
      UPDATE academic_v2_terms
      SET start_date = $1,
          updated_at = NOW()
      WHERE term_number = 1
        AND is_active = TRUE
        AND is_archived = FALSE
        AND (start_date IS NULL OR start_date < $2)
    `, [AUTUMN_START_DATE, STALE_BEFORE_DATE]);
  }

  if (await tableExists(pool, 'semesters')) {
    await pool.query(`
      UPDATE semesters
      SET start_date = $1
      WHERE is_active = 1
        AND is_archived = 0
        AND (start_date IS NULL OR start_date < $2)
    `, [AUTUMN_START_DATE, STALE_BEFORE_DATE]);
  }
}

module.exports = { id: '078_align_active_autumn_calendar_2026', up };
