const statements = [
  `
    CREATE INDEX IF NOT EXISTS idx_users_telegram_id_linked
    ON users (telegram_id)
    WHERE telegram_id IS NOT NULL AND telegram_id <> ''
  `,
  'CREATE INDEX IF NOT EXISTS idx_users_course_id ON users (course_id, id)',
  'CREATE INDEX IF NOT EXISTS idx_users_group_id ON users (group_id, id)',
  `
    CREATE INDEX IF NOT EXISTS idx_schedule_entries_course_semester_week_slot
    ON schedule_entries (course_id, semester_id, week_number, day_of_week, class_number, subject_id, group_number)
  `,
  `
    CREATE INDEX IF NOT EXISTS idx_schedule_entries_subject_course_semester
    ON schedule_entries (subject_id, course_id, semester_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS idx_homework_subject_class_date_slot
    ON homework (subject_id, class_date, class_number, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS idx_homework_subject_course_semester_created
    ON homework (subject_id, course_id, semester_id, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS idx_homework_subject_course_semester_due
    ON homework (subject_id, course_id, semester_id, custom_due_date, created_at DESC)
    WHERE custom_due_date IS NOT NULL
  `,
  'CREATE INDEX IF NOT EXISTS idx_message_targets_user_message ON message_targets (user_id, message_id)',
  'CREATE INDEX IF NOT EXISTS idx_message_targets_message_user ON message_targets (message_id, user_id)',
  `
    CREATE INDEX IF NOT EXISTS idx_messages_course_semester_created
    ON messages (course_id, semester_id, created_at DESC, id DESC)
  `,
  'CREATE INDEX IF NOT EXISTS idx_messages_subject_created ON messages (subject_id, created_at DESC, id DESC)',
  `
    CREATE INDEX IF NOT EXISTS idx_teamwork_tasks_subject_course_semester_created
    ON teamwork_tasks (subject_id, course_id, semester_id, created_at DESC)
  `,
  'CREATE INDEX IF NOT EXISTS idx_teamwork_groups_task_id ON teamwork_groups (task_id, id)',
  'CREATE INDEX IF NOT EXISTS idx_teamwork_members_group_user ON teamwork_members (group_id, user_id)',
  'CREATE INDEX IF NOT EXISTS idx_history_log_course_created ON history_log (course_id, created_at DESC)',
  'CREATE INDEX IF NOT EXISTS idx_history_log_actor_created ON history_log (actor_id, created_at DESC)',
];

async function up(pool) {
  for (const statement of statements) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '062_db_performance_indexes',
  up,
};
