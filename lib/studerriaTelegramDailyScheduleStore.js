const truthy = (column) => `COALESCE(LOWER(TRIM(CAST(${column} AS TEXT))), '1') IN ('1', 'true', 't', 'yes', 'on')`;

function createDailyScheduleStore(db) {
  return {
    async loadCourse(config) {
      const rows = await db.all(`
        SELECT g.id AS group_id, g.legacy_course_id AS course_id, g.campus_key,
               g.label, p.name AS program_name, c.admission_year
        FROM academic_v2_groups g
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        JOIN academic_v2_programs p ON p.id = c.program_id
        WHERE ${truthy('g.is_active')} AND ${truthy('c.is_active')} AND ${truthy('p.is_active')}
          AND p.track_key IN ('bachelor', 'master')
          AND ${config.courseId ? 'g.legacy_course_id = ?' : 'g.id = (SELECT group_id FROM users WHERE telegram_id = ?)'}
      `, [config.courseId || config.actorTelegramId]);
      if (rows.length !== 1 || !rows[0].course_id) {
        throw new Error('Для розсилки потрібен один активний студентський курс. Перевір STUDERRIA_TG_DAILY_SCHEDULE_COURSE_ID.');
      }
      return rows[0];
    },

    async loadStudents(course) {
      return db.all(`
        SELECT u.id, u.full_name, u.role, u.group_id, u.course_id, u.schedule_group,
               u.study_context_id, u.telegram_id, u.telegram_username
        FROM users u
        JOIN academic_v2_groups g ON g.id = u.group_id
        WHERE g.id = ? AND g.legacy_course_id = ?
          AND ${truthy('u.is_active')} AND ${truthy('g.is_active')}
          AND TRIM(COALESCE(u.telegram_id, '')) ~ '^[1-9][0-9]*$'
          AND (
            EXISTS (
              SELECT 1 FROM user_roles ur JOIN access_roles ar ON ar.id = ur.role_id
              WHERE ur.user_id = u.id AND ar.is_active = true AND ar.key IN ('student', 'starosta')
            ) OR (
              NOT EXISTS (
                SELECT 1 FROM user_roles ur JOIN access_roles ar ON ar.id = ur.role_id
                WHERE ur.user_id = u.id AND ar.is_active = true
              ) AND LOWER(TRIM(u.role)) IN ('student', 'starosta')
            )
          )
        ORDER BY u.id
      `, [course.group_id, course.course_id]);
    },

    async claimDelivery(delivery) {
      return db.get(`
        INSERT INTO telegram_daily_schedule_deliveries
          (delivery_key, mode, target_date, chat_id, thread_id, course_id, status)
        VALUES (?, ?, ?, ?, ?, ?, 'sending')
        ON CONFLICT (delivery_key) DO NOTHING
        RETURNING id
      `, [delivery.key, delivery.mode, delivery.targetIso, delivery.chatId,
        delivery.threadId || null, delivery.courseId]);
    },

    async finishDelivery(id, status, messageId = null, error = null) {
      await db.run(`
        UPDATE telegram_daily_schedule_deliveries
        SET status = ?, message_id = ?, error = ?, updated_at = NOW()
        WHERE id = ?
      `, [status, messageId, error ? String(error).slice(0, 1000) : null, id]);
    },
  };
}

module.exports = { createDailyScheduleStore };
