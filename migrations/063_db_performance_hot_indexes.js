const statements = [
  `
    CREATE INDEX IF NOT EXISTS idx_academic_v2_schedule_entries_term_week_slot
    ON academic_v2_schedule_entries (term_id, week_number, day_of_week, class_number, group_subject_activity_id, group_number)
  `,
  `
    CREATE INDEX IF NOT EXISTS idx_academic_v2_group_subjects_group_legacy
    ON academic_v2_group_subjects (group_id, legacy_subject_id, id)
  `,
  `
    CREATE INDEX IF NOT EXISTS idx_academic_v2_student_enrollments_user_primary
    ON academic_v2_student_enrollments (user_id, is_primary, group_id)
  `,
  'CREATE INDEX IF NOT EXISTS idx_message_reads_user_message ON message_reads (user_id, message_id)',
  'CREATE INDEX IF NOT EXISTS idx_homework_tag_map_tag_homework ON homework_tag_map (tag_id, homework_id)',
  'CREATE INDEX IF NOT EXISTS idx_subgroups_homework_id ON subgroups (homework_id, id)',
  'CREATE INDEX IF NOT EXISTS idx_subgroup_members_member_subgroup ON subgroup_members (member_username, subgroup_id)',
  'CREATE INDEX IF NOT EXISTS idx_homework_status_scheduled ON homework (status, scheduled_at, created_at DESC)',
  'CREATE INDEX IF NOT EXISTS idx_messages_status_scheduled ON messages (status, scheduled_at, created_at DESC, id DESC)',
  `
    CREATE INDEX IF NOT EXISTS idx_site_visit_events_retention
    ON site_visit_events (created_at)
    WHERE COALESCE(is_frozen, false) = false
  `,
  `
    CREATE INDEX IF NOT EXISTS idx_login_history_retention
    ON login_history (created_at)
    WHERE COALESCE(is_frozen, false) = false
  `,
  `
    CREATE INDEX IF NOT EXISTS idx_activity_log_course_created
    ON activity_log (course_id, created_at DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS idx_history_log_action_created
    ON history_log (action, created_at DESC)
  `,
];

async function up(pool) {
  for (const statement of statements) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '063_db_performance_hot_indexes',
  up,
};
