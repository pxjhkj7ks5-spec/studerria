const truthy = (column) => `COALESCE(LOWER(TRIM(CAST(${column} AS TEXT))), '1') IN ('1', 'true', 't', 'yes', 'on')`;

function createDailyScheduleStore(db) {
  return {
    async importLegacyBinding(config = {}) {
      const courseId = Number(config.courseId);
      const chatId = String(config.chatId || '').trim();
      const threadId = Number(config.threadId) > 0 ? Number(config.threadId) : null;
      const canImport = config.enabled && Number.isSafeInteger(courseId) && courseId > 0
        && /^-?[1-9][0-9]*$/.test(chatId);
      const row = await db.get(`
        WITH marker AS (
          INSERT INTO settings (key, value)
          VALUES ('telegram_daily_schedule_legacy_import_v1', 'complete')
          ON CONFLICT (key) DO NOTHING
          RETURNING key
        ), candidate AS (
          SELECT g.id AS academic_group_id
          FROM academic_v2_groups g
          JOIN academic_v2_cohorts c ON c.id = g.cohort_id
          JOIN academic_v2_programs p ON p.id = c.program_id
          WHERE ? = TRUE
            AND g.legacy_course_id = ?
            AND ${truthy('g.is_active')}
            AND ${truthy('c.is_active')}
            AND ${truthy('p.is_active')}
            AND p.track_key IN ('bachelor', 'master')
          LIMIT 1
        )
        INSERT INTO telegram_daily_schedule_bindings
          (academic_group_id, chat_id, thread_id, is_enabled)
        SELECT candidate.academic_group_id, ?, ?, TRUE
        FROM candidate
        CROSS JOIN marker
        ON CONFLICT (chat_id, (COALESCE(thread_id, 0))) DO NOTHING
        RETURNING id
      `, [canImport, courseId || null, chatId || '0', threadId]);
      return row || null;
    },

    async listEligibleGroups() {
      return db.all(`
        SELECT g.id AS academic_group_id, g.legacy_course_id AS course_id, g.campus_key,
               g.label, g.stage_number, p.name AS program_name, c.admission_year
        FROM academic_v2_groups g
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        JOIN academic_v2_programs p ON p.id = c.program_id
        WHERE ${truthy('g.is_active')} AND ${truthy('c.is_active')} AND ${truthy('p.is_active')}
          AND p.track_key IN ('bachelor', 'master')
          AND g.legacy_course_id IS NOT NULL
        ORDER BY c.admission_year DESC, p.name ASC, g.stage_number ASC, g.campus_key ASC, g.id ASC
      `);
    },

    async listBindings({ activeOnly = false } = {}) {
      return db.all(`
        SELECT b.id, b.academic_group_id, b.chat_id, b.thread_id, b.is_enabled,
               b.created_by, b.updated_by, b.created_at, b.updated_at,
               g.legacy_course_id AS course_id, g.campus_key, g.label, g.stage_number,
               p.name AS program_name, c.admission_year,
               latest.status AS last_status, latest.target_date AS last_target_date,
               latest.error AS last_error, latest.updated_at AS last_delivery_at
        FROM telegram_daily_schedule_bindings b
        JOIN academic_v2_groups g ON g.id = b.academic_group_id
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        JOIN academic_v2_programs p ON p.id = c.program_id
        LEFT JOIN LATERAL (
          SELECT d.status, d.target_date, d.error, d.updated_at
          FROM telegram_daily_schedule_deliveries d
          WHERE d.binding_id = b.id
          ORDER BY d.created_at DESC, d.id DESC
          LIMIT 1
        ) latest ON TRUE
        ${activeOnly ? `WHERE ${truthy('b.is_enabled')} AND ${truthy('g.is_active')}
          AND ${truthy('c.is_active')} AND ${truthy('p.is_active')}` : ''}
        ORDER BY b.is_enabled DESC, c.admission_year DESC, p.name ASC, b.id ASC
      `);
    },

    async getBinding(id, { activeOnly = false } = {}) {
      const rows = await this.listBindings({ activeOnly });
      return rows.find((row) => Number(row.id) === Number(id)) || null;
    },

    async createBinding(input) {
      return db.get(`
        INSERT INTO telegram_daily_schedule_bindings
          (academic_group_id, chat_id, thread_id, is_enabled, created_by, updated_by)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING *
      `, [input.academicGroupId, input.chatId, input.threadId || null,
        input.isEnabled !== false, input.actorId || null, input.actorId || null]);
    },

    async updateBinding(id, input) {
      return db.get(`
        UPDATE telegram_daily_schedule_bindings
        SET academic_group_id = ?, chat_id = ?, thread_id = ?, is_enabled = ?,
            updated_by = ?, updated_at = NOW()
        WHERE id = ?
        RETURNING *
      `, [input.academicGroupId, input.chatId, input.threadId || null,
        input.isEnabled !== false, input.actorId || null, id]);
    },

    async setBindingEnabled(id, isEnabled, actorId = null) {
      return db.get(`
        UPDATE telegram_daily_schedule_bindings
        SET is_enabled = ?, updated_by = ?, updated_at = NOW()
        WHERE id = ?
        RETURNING *
      `, [Boolean(isEnabled), actorId || null, id]);
    },

    async deleteBinding(id) {
      return db.get('DELETE FROM telegram_daily_schedule_bindings WHERE id = ? RETURNING *', [id]);
    },

    async loadCourse(config) {
      const rows = await db.all(`
        SELECT g.id AS group_id, g.legacy_course_id AS course_id, g.campus_key,
               g.label, p.name AS program_name, c.admission_year
        FROM academic_v2_groups g
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        JOIN academic_v2_programs p ON p.id = c.program_id
        WHERE ${truthy('g.is_active')} AND ${truthy('c.is_active')} AND ${truthy('p.is_active')}
          AND p.track_key IN ('bachelor', 'master')
          AND ${config.groupId ? 'g.id = ?' : (config.courseId ? 'g.legacy_course_id = ?' : 'g.id = (SELECT group_id FROM users WHERE telegram_id = ?)')}
      `, [config.groupId || config.courseId || config.actorTelegramId]);
      if (rows.length !== 1 || !rows[0].course_id) {
        throw new Error('Для розсилки потрібен один активний студентський курс. Перевір STUDERRIA_TG_DAILY_SCHEDULE_COURSE_ID.');
      }
      return rows[0];
    },

    async loadStudents(course) {
      return db.all(`
        SELECT u.id, u.full_name, u.role, u.group_id, u.course_id, u.schedule_group,
               u.study_context_id, u.telegram_id, u.telegram_username
               , u.show_full_schedule
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
          (delivery_key, mode, target_date, chat_id, thread_id, course_id, binding_id, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'sending')
        ON CONFLICT (delivery_key) DO NOTHING
        RETURNING id
      `, [delivery.key, delivery.mode, delivery.targetIso, delivery.chatId,
        delivery.threadId || null, delivery.courseId, delivery.bindingId || null]);
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
