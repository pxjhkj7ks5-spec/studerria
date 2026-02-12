const ddl = [
  `
    DELETE FROM schedule_generator_entries a
    USING schedule_generator_entries b
    WHERE a.id > b.id
      AND a.run_id = b.run_id
      AND a.course_id = b.course_id
      AND a.group_number = b.group_number
      AND a.week_number = b.week_number
      AND a.day_of_week = b.day_of_week
      AND a.class_number = b.class_number
      AND a.semester_id IS NOT DISTINCT FROM b.semester_id
  `,
  'CREATE INDEX IF NOT EXISTS schedule_generator_items_run_course_idx ON schedule_generator_items(run_id, course_id)',
  'CREATE INDEX IF NOT EXISTS schedule_generator_items_run_subject_idx ON schedule_generator_items(run_id, subject_id)',
  'CREATE INDEX IF NOT EXISTS schedule_generator_entries_run_course_idx ON schedule_generator_entries(run_id, course_id)',
  'CREATE INDEX IF NOT EXISTS schedule_generator_entries_run_course_semester_idx ON schedule_generator_entries(run_id, course_id, semester_id)',
  'CREATE INDEX IF NOT EXISTS schedule_generator_entries_run_teacher_slot_idx ON schedule_generator_entries(run_id, teacher_id, week_number, day_of_week, class_number)',
  `
    CREATE UNIQUE INDEX IF NOT EXISTS schedule_generator_entries_run_slot_unique
    ON schedule_generator_entries(
      run_id,
      course_id,
      COALESCE(semester_id, -1),
      group_number,
      week_number,
      day_of_week,
      class_number
    )
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '011_schedule_generator_indexes',
  up,
};

