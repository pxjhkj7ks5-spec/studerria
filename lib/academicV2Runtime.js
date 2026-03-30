function cleanText(value, maxLength = 160) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, Math.max(1, Number(maxLength) || 1));
}

function normalizePositiveInt(value) {
  const normalized = Number(value || 0);
  return Number.isInteger(normalized) && normalized > 0 ? normalized : null;
}

function normalizeBoolean(value, fallback = false) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1;
  const normalized = String(value || '').trim().toLowerCase();
  if (['1', 'true', 'on', 'yes'].includes(normalized)) return true;
  if (['0', 'false', 'off', 'no'].includes(normalized)) return false;
  return fallback === true;
}

function buildEmptyProjectionIssues() {
  return {
    has_issues: false,
    missing_scope: false,
    missing_active_term: false,
    missing_legacy_course: false,
    missing_legacy_semester: false,
    unmapped_subjects: [],
  };
}

function finalizeProjectionIssues(issues = {}) {
  const normalized = {
    ...buildEmptyProjectionIssues(),
    ...(issues || {}),
  };
  normalized.unmapped_subjects = Array.isArray(normalized.unmapped_subjects)
    ? normalized.unmapped_subjects
    : [];
  normalized.has_issues = Boolean(
    normalized.missing_scope
    || normalized.missing_active_term
    || normalized.missing_legacy_course
    || normalized.missing_legacy_semester
    || normalized.unmapped_subjects.length
  );
  return normalized;
}

function buildScheduleGroupLabel(hasAllGroups, groupNumbers = []) {
  if (hasAllGroups) {
    return 'All groups';
  }
  if (groupNumbers.length === 1) {
    return `Group ${groupNumbers[0]}`;
  }
  if (groupNumbers.length > 1) {
    return `Groups ${groupNumbers.join(', ')}`;
  }
  return 'No groups';
}

function normalizeGroupNumberArray(value, maxGroupCount = null) {
  const values = Array.isArray(value) ? value : [value];
  const normalizedMax = normalizePositiveInt(maxGroupCount);
  return Array.from(new Set(
    values
      .map((item) => Number(item || 0))
      .filter((item) => Number.isInteger(item) && item > 0)
      .filter((item) => !normalizedMax || item <= normalizedMax)
  )).sort((a, b) => a - b);
}

const COURSE_SCOPE_SELECT = `
  SELECT
    g.id AS group_id,
    g.label AS group_label,
    g.code AS group_code,
    g.stage_number,
    g.campus_key,
    g.legacy_course_id,
    g.legacy_study_context_id,
    legacy_course.name AS legacy_course_name,
    c.id AS cohort_id,
    c.label AS cohort_label,
    c.admission_year,
    c.legacy_admission_id,
    p.id AS program_id,
    p.code AS program_code,
    p.name AS program_name,
    p.track_key
  FROM academic_v2_groups g
  JOIN academic_v2_cohorts c ON c.id = g.cohort_id
  JOIN academic_v2_programs p ON p.id = c.program_id
  LEFT JOIN courses legacy_course ON legacy_course.id = g.legacy_course_id
  WHERE COALESCE(g.is_active, TRUE) = TRUE
    AND COALESCE(c.is_active, TRUE) = TRUE
    AND COALESCE(p.is_active, TRUE) = TRUE
`;

function mapCourseScopeRow(row) {
  if (!row) return null;
  return {
    group_id: Number(row.group_id || 0),
    group_label: cleanText(row.group_label, 160),
    group_code: cleanText(row.group_code, 80),
    stage_number: Math.max(1, Number(row.stage_number || 0) || 1),
    campus_key: cleanText(row.campus_key, 20) || 'kyiv',
    legacy_course_id: normalizePositiveInt(row.legacy_course_id),
    legacy_course_name: cleanText(row.legacy_course_name, 160),
    legacy_study_context_id: normalizePositiveInt(row.legacy_study_context_id),
    cohort_id: Number(row.cohort_id || 0),
    cohort_label: cleanText(row.cohort_label, 160),
    admission_year: Number(row.admission_year || 0) || null,
    legacy_admission_id: normalizePositiveInt(row.legacy_admission_id),
    program_id: Number(row.program_id || 0),
    program_code: cleanText(row.program_code, 80),
    program_name: cleanText(row.program_name, 160),
    track_key: cleanText(row.track_key, 20) || 'bachelor',
  };
}

function mapTermRow(row) {
  if (!row) return null;
  return {
    id: Number(row.id || 0),
    group_id: Number(row.group_id || 0),
    term_number: Math.max(1, Number(row.term_number || 0) || 1),
    title: cleanText(row.title, 160),
    start_date: cleanText(row.start_date, 20),
    weeks_count: Math.max(1, Number(row.weeks_count || 0) || 16),
    is_active: normalizeBoolean(row.is_active, false),
    is_archived: normalizeBoolean(row.is_archived, false),
    legacy_semester_id: normalizePositiveInt(row.legacy_semester_id),
  };
}

async function getCourseScopeByLegacyCourse(store, courseId) {
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedCourseId || !store || typeof store.get !== 'function') {
    return null;
  }
  const row = await store.get(
    `
      ${COURSE_SCOPE_SELECT}
        AND g.legacy_course_id = ?
      LIMIT 1
    `,
    [normalizedCourseId]
  );
  return mapCourseScopeRow(row);
}

async function getActiveTermForGroup(store, groupId) {
  const normalizedGroupId = normalizePositiveInt(groupId);
  if (!normalizedGroupId || !store || typeof store.get !== 'function') {
    return null;
  }
  const row = await store.get(
    `
      SELECT
        id,
        group_id,
        term_number,
        title,
        start_date,
        weeks_count,
        is_active,
        is_archived,
        legacy_semester_id
      FROM academic_v2_terms
      WHERE group_id = ?
        AND COALESCE(is_active, FALSE) = TRUE
      ORDER BY term_number ASC, id ASC
      LIMIT 1
    `,
    [normalizedGroupId]
  );
  return mapTermRow(row);
}

async function loadCourseProjectionState(store, courseId) {
  const scope = await getCourseScopeByLegacyCourse(store, courseId);
  if (!scope) {
    return {
      scope: null,
      term: null,
      projectionIssues: finalizeProjectionIssues({ missing_scope: true }),
    };
  }
  const term = await getActiveTermForGroup(store, scope.group_id);
  return {
    scope,
    term,
    projectionIssues: finalizeProjectionIssues({
      missing_legacy_course: !scope.legacy_course_id,
      missing_active_term: !term,
      missing_legacy_semester: Boolean(term) && !term.legacy_semester_id,
    }),
  };
}

async function loadCourseSubjectScope(store, courseId, options = {}) {
  const visibleOnly = options.visibleOnly === true;
  const teamworkOnly = options.teamworkOnly === true;
  const courseState = await loadCourseProjectionState(store, courseId);
  if (!courseState.scope) {
    return {
      ...courseState,
      subjects: [],
      subject_ids: [],
      owner_course_ids: [],
      owner_semester_ids: [],
      subject_map: new Map(),
    };
  }

  const params = [courseState.scope.group_id];
  let termClause = '';
  if (courseState.term) {
    termClause = `
      AND EXISTS (
        SELECT 1
        FROM academic_v2_group_subject_terms gst
        WHERE gst.group_subject_id = gs.id
          AND gst.term_id = ?
      )
    `;
    params.push(courseState.term.id);
  }

  const rows = await store.all(
    `
      SELECT
        gs.id AS group_subject_id,
        gs.legacy_subject_id,
        gs.title AS subject_name,
        gs.title,
        gs.group_count,
        gs.default_group,
        gs.is_visible,
        gs.is_required,
        gs.is_general,
        gs.show_in_teamwork,
        gs.sort_order,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT ta.user_id), NULL),
          ARRAY[]::int[]
        ) AS teacher_ids
      FROM academic_v2_group_subjects gs
      LEFT JOIN academic_v2_teacher_assignments ta ON ta.group_subject_id = gs.id
      WHERE gs.group_id = ?
        ${visibleOnly ? 'AND COALESCE(gs.is_visible, TRUE) = TRUE' : ''}
        ${teamworkOnly ? 'AND COALESCE(gs.show_in_teamwork, TRUE) = TRUE' : ''}
        ${termClause}
      GROUP BY gs.id
      ORDER BY gs.sort_order ASC, gs.title ASC, gs.id ASC
    `,
    params
  );

  const unmappedSubjects = [];
  const subjects = [];
  for (const row of rows || []) {
    const legacySubjectId = normalizePositiveInt(row.legacy_subject_id);
    const normalizedRow = {
      id: legacySubjectId,
      subject_id: legacySubjectId,
      legacy_subject_id: legacySubjectId,
      group_subject_id: Number(row.group_subject_id || 0),
      subject_name: cleanText(row.subject_name, 160),
      title: cleanText(row.title, 160),
      name: cleanText(row.subject_name, 160),
      course_id: normalizePositiveInt(courseState.scope.legacy_course_id),
      owner_course_id: normalizePositiveInt(courseState.scope.legacy_course_id),
      course_name: cleanText(courseState.scope.legacy_course_name, 160),
      group_id: Number(courseState.scope.group_id || 0),
      group_label: cleanText(courseState.scope.group_label, 160),
      group_count: Math.max(1, Number(row.group_count || 0) || 1),
      default_group: Math.max(1, Number(row.default_group || 0) || 1),
      is_visible: normalizeBoolean(row.is_visible, true),
      is_required: normalizeBoolean(row.is_required, true),
      is_general: normalizeBoolean(row.is_general, true),
      show_in_teamwork: normalizeBoolean(row.show_in_teamwork, true),
      sort_order: Number(row.sort_order || 0) || 0,
      teacher_ids: Array.isArray(row.teacher_ids) ? row.teacher_ids.map((value) => Number(value || 0)).filter((value) => value > 0) : [],
      legacy_semester_id: normalizePositiveInt(courseState.term && courseState.term.legacy_semester_id),
      term_id: courseState.term ? Number(courseState.term.id || 0) : null,
      term_title: courseState.term ? cleanText(courseState.term.title, 160) : '',
      term_number: courseState.term ? Math.max(1, Number(courseState.term.term_number || 0) || 1) : null,
      has_all_groups: normalizeBoolean(row.is_general, true),
      group_numbers: normalizeBoolean(row.is_general, true)
        ? Array.from({ length: Math.max(1, Number(row.group_count || 0) || 1) }, (_v, index) => index + 1)
        : [],
      group_label: normalizeBoolean(row.is_general, true) ? 'Усі групи' : '',
    };
    if (!legacySubjectId) {
      unmappedSubjects.push({
        group_subject_id: normalizedRow.group_subject_id,
        subject_title: normalizedRow.subject_name || normalizedRow.title,
      });
      continue;
    }
    subjects.push(normalizedRow);
  }

  const projectionIssues = finalizeProjectionIssues({
    ...(courseState.projectionIssues || {}),
    unmapped_subjects: unmappedSubjects,
  });
  const ownerCourseIds = Array.from(new Set(
    subjects
      .map((subject) => Number(subject.owner_course_id || 0))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const ownerSemesterIds = Array.from(new Set(
    subjects
      .map((subject) => Number(subject.legacy_semester_id || 0))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const subjectIds = Array.from(new Set(
    subjects
      .map((subject) => Number(subject.subject_id || 0))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  return {
    ...courseState,
    subjects,
    subject_ids: subjectIds,
    owner_course_ids: ownerCourseIds,
    owner_semester_ids: ownerSemesterIds,
    subject_map: new Map(subjects.map((subject) => [Number(subject.subject_id || 0), subject])),
    projectionIssues,
  };
}

async function listTeacherAssignedSubjectRows(store, userId, options = {}) {
  const normalizedUserId = normalizePositiveInt(userId);
  const normalizedCourseId = normalizePositiveInt(options.courseId);
  if (!normalizedUserId || !store || typeof store.all !== 'function') {
    return [];
  }
  const includeHidden = options.includeHidden === true;
  const params = [normalizedUserId];
  let courseClause = '';
  if (normalizedCourseId) {
    courseClause = 'AND g.legacy_course_id = ?';
    params.push(normalizedCourseId);
  }
  const rows = await store.all(
    `
      SELECT
        gs.id AS group_subject_id,
        gs.legacy_subject_id,
        gs.title AS subject_name,
        gs.group_count,
        gs.default_group,
        gs.is_visible,
        gs.is_required,
        gs.is_general,
        gs.show_in_teamwork,
        g.id AS group_id,
        g.label AS group_label,
        g.legacy_course_id,
        legacy_course.name AS course_name,
        term.id AS term_id,
        term.term_number,
        term.title AS term_title,
        term.legacy_semester_id
      FROM academic_v2_teacher_assignments ta
      JOIN academic_v2_group_subjects gs ON gs.id = ta.group_subject_id
      JOIN academic_v2_groups g ON g.id = gs.group_id
      LEFT JOIN courses legacy_course ON legacy_course.id = g.legacy_course_id
      LEFT JOIN LATERAL (
        SELECT t.id, t.term_number, t.title, t.legacy_semester_id
        FROM academic_v2_group_subject_terms gst
        JOIN academic_v2_terms t ON t.id = gst.term_id
        WHERE gst.group_subject_id = gs.id
          AND COALESCE(t.is_active, FALSE) = TRUE
        ORDER BY t.term_number ASC, t.id ASC
        LIMIT 1
      ) term ON true
      WHERE ta.user_id = ?
        AND COALESCE(g.is_active, TRUE) = TRUE
        ${includeHidden ? '' : 'AND COALESCE(gs.is_visible, TRUE) = TRUE'}
        ${courseClause}
      ORDER BY COALESCE(g.legacy_course_id, 0) ASC, gs.sort_order ASC, gs.title ASC, gs.id ASC
    `,
    params
  );

  return (rows || []).map((row) => ({
    subject_id: normalizePositiveInt(row.legacy_subject_id),
    legacy_subject_id: normalizePositiveInt(row.legacy_subject_id),
    group_subject_id: Number(row.group_subject_id || 0),
    subject_name: cleanText(row.subject_name, 160),
    group_number: null,
    course_id: normalizePositiveInt(row.legacy_course_id),
    owner_course_id: normalizePositiveInt(row.legacy_course_id),
    course_name: cleanText(row.course_name, 160),
    group_count: Math.max(1, Number(row.group_count || 0) || 1),
    default_group: Math.max(1, Number(row.default_group || 0) || 1),
    is_visible: normalizeBoolean(row.is_visible, true),
    is_required: normalizeBoolean(row.is_required, true),
    is_general: normalizeBoolean(row.is_general, true),
    show_in_teamwork: normalizeBoolean(row.show_in_teamwork, true),
    group_id: Number(row.group_id || 0),
    group_label: cleanText(row.group_label, 160),
    term_id: normalizePositiveInt(row.term_id),
    term_number: Number(row.term_number || 0) || null,
    term_title: cleanText(row.term_title, 160),
    legacy_semester_id: normalizePositiveInt(row.legacy_semester_id),
  }));
}

async function listTeacherAssignedSubjectRowsByUsers(store, options = {}) {
  const normalizedUserIds = Array.from(new Set(
    (Array.isArray(options.userIds) ? options.userIds : [options.userIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const normalizedSubjectId = normalizePositiveInt(options.subjectId);
  const includeHidden = options.includeHidden === true;
  if (!normalizedUserIds.length || !normalizedSubjectId || !store || typeof store.all !== 'function') {
    return [];
  }
  const rows = await store.all(
    `
      SELECT
        ta.user_id,
        gs.id AS group_subject_id,
        gs.legacy_subject_id,
        gs.title AS subject_name,
        gs.group_count,
        gs.default_group,
        gs.is_visible,
        gs.is_required,
        gs.is_general,
        gs.show_in_teamwork,
        g.id AS group_id,
        g.label AS group_label,
        g.legacy_course_id,
        legacy_course.name AS course_name,
        term.id AS term_id,
        term.term_number,
        term.title AS term_title,
        term.legacy_semester_id
      FROM academic_v2_teacher_assignments ta
      JOIN academic_v2_group_subjects gs ON gs.id = ta.group_subject_id
      JOIN academic_v2_groups g ON g.id = gs.group_id
      LEFT JOIN courses legacy_course ON legacy_course.id = g.legacy_course_id
      LEFT JOIN LATERAL (
        SELECT t.id, t.term_number, t.title, t.legacy_semester_id
        FROM academic_v2_group_subject_terms gst
        JOIN academic_v2_terms t ON t.id = gst.term_id
        WHERE gst.group_subject_id = gs.id
          AND COALESCE(t.is_active, FALSE) = TRUE
        ORDER BY t.term_number ASC, t.id ASC
        LIMIT 1
      ) term ON true
      WHERE ta.user_id = ANY(?::int[])
        AND COALESCE(gs.legacy_subject_id, 0) = ?
        AND COALESCE(g.is_active, TRUE) = TRUE
        ${includeHidden ? '' : 'AND COALESCE(gs.is_visible, TRUE) = TRUE'}
      ORDER BY ta.user_id ASC, COALESCE(g.legacy_course_id, 0) ASC, gs.sort_order ASC, gs.title ASC, gs.id ASC
    `,
    [normalizedUserIds, normalizedSubjectId]
  );
  return (rows || []).map((row) => ({
    user_id: Number(row.user_id || 0),
    subject_id: normalizePositiveInt(row.legacy_subject_id),
    legacy_subject_id: normalizePositiveInt(row.legacy_subject_id),
    group_subject_id: Number(row.group_subject_id || 0),
    subject_name: cleanText(row.subject_name, 160),
    group_number: null,
    course_id: normalizePositiveInt(row.legacy_course_id),
    owner_course_id: normalizePositiveInt(row.legacy_course_id),
    course_name: cleanText(row.course_name, 160),
    group_count: Math.max(1, Number(row.group_count || 0) || 1),
    default_group: Math.max(1, Number(row.default_group || 0) || 1),
    is_visible: normalizeBoolean(row.is_visible, true),
    is_required: normalizeBoolean(row.is_required, true),
    is_general: normalizeBoolean(row.is_general, true),
    show_in_teamwork: normalizeBoolean(row.show_in_teamwork, true),
    group_id: Number(row.group_id || 0),
    group_label: cleanText(row.group_label, 160),
    term_id: normalizePositiveInt(row.term_id),
    term_number: Number(row.term_number || 0) || null,
    term_title: cleanText(row.term_title, 160),
    legacy_semester_id: normalizePositiveInt(row.legacy_semester_id),
  }));
}

async function listCourseUsersByLegacyCourse(store, courseId, options = {}) {
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedCourseId || !store || typeof store.all !== 'function') {
    return [];
  }
  const activeOnly = options.activeOnly === true;
  const normalizedUserIds = Array.from(new Set(
    (Array.isArray(options.userIds) ? options.userIds : [options.userIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const normalizedExcludeRoles = Array.from(new Set(
    (Array.isArray(options.excludeRoles) ? options.excludeRoles : [options.excludeRoles])
      .map((value) => cleanText(value, 40).toLowerCase())
      .filter(Boolean)
  ));
  const where = [
    `(
      COALESCE(v2_group.legacy_course_id, 0) = ?
      OR (
        u.group_id IS NULL
        AND COALESCE(u.course_id, 0) = ?
      )
    )`,
  ];
  const params = [normalizedCourseId, normalizedCourseId];
  if (normalizedUserIds.length) {
    where.push('u.id = ANY(?::int[])');
    params.push(normalizedUserIds);
  }
  if (normalizedExcludeRoles.length) {
    where.push("NOT (LOWER(TRIM(COALESCE(u.role, ''))) = ANY(?::text[]))");
    params.push(normalizedExcludeRoles);
  }
  if (activeOnly) {
    where.push("COALESCE(LOWER(TRIM(CAST(u.is_active AS TEXT))), '1') IN ('1', 'true', 't', 'yes', 'on', '')");
  }
  const rows = await store.all(
    `
      SELECT
        u.*,
        v2_group.id AS academic_group_id,
        v2_group.label AS academic_group_label,
        v2_group.legacy_course_id AS academic_legacy_course_id
      FROM users u
      LEFT JOIN academic_v2_groups v2_group ON v2_group.id = u.group_id
      WHERE ${where.join(' AND ')}
      ORDER BY u.full_name ASC, u.id ASC
    `,
    params
  );
  return Array.isArray(rows) ? rows : [];
}

async function loadCourseScheduleRows(store, courseId, options = {}) {
  const normalizedWeekNumber = Math.max(1, Number(options.weekNumber || 0) || 1);
  const courseState = await loadCourseSubjectScope(store, courseId, {
    visibleOnly: options.visibleOnly === true,
  });
  if (!courseState.scope || !courseState.term) {
    return {
      ...courseState,
      scheduleRows: [],
      projectionIssues: finalizeProjectionIssues(courseState.projectionIssues),
    };
  }

  const rows = await store.all(
    `
      SELECT
        se.id AS schedule_entry_id,
        se.group_subject_id,
        se.group_subject_activity_id,
        se.group_number,
        se.target_group_numbers,
        se.day_of_week,
        se.class_number,
        se.week_number,
        se.lesson_type,
        activity.activity_type,
        gs.legacy_subject_id,
        gs.title AS subject_title,
        gs.is_general,
        gs.group_count,
        gs.default_group,
        st.name AS template_name
      FROM academic_v2_schedule_entries se
      JOIN academic_v2_group_subject_activities activity ON activity.id = se.group_subject_activity_id
      JOIN academic_v2_group_subjects gs ON gs.id = activity.group_subject_id
      JOIN academic_v2_subject_templates st ON st.id = gs.subject_template_id
      WHERE gs.group_id = ?
        AND se.term_id = ?
        AND se.week_number = ?
        ${options.visibleOnly === true ? 'AND COALESCE(gs.is_visible, TRUE) = TRUE' : ''}
      ORDER BY se.day_of_week ASC, se.class_number ASC, COALESCE(se.group_number, 1) ASC, se.id ASC
    `,
    [courseState.scope.group_id, courseState.term.id, normalizedWeekNumber]
  );

  const subjectById = new Map(
    (courseState.subjects || []).map((subject) => [Number(subject.subject_id || 0), subject])
  );
  const scheduleRows = [];
  const unmappedScheduleEntries = [];
  const compatCourseId = normalizePositiveInt(courseState.scope.legacy_course_id);
  const compatSemesterId = normalizePositiveInt(courseState.term.legacy_semester_id);

  (rows || []).forEach((row) => {
    const legacySubjectId = normalizePositiveInt(row.legacy_subject_id);
    const subject = legacySubjectId ? subjectById.get(legacySubjectId) : null;
    if (!legacySubjectId || !compatCourseId) {
      unmappedScheduleEntries.push({
        schedule_entry_id: Number(row.schedule_entry_id || 0),
        group_subject_id: Number(row.group_subject_id || 0),
        subject_title: cleanText(row.subject_title || row.template_name, 160),
      });
      return;
    }

    const activityType = cleanText(row.activity_type || row.lesson_type, 40).toLowerCase() || 'lecture';
    const targetGroupNumbers = activityType === 'lecture'
      ? []
      : normalizeGroupNumberArray(
        Array.isArray(row.target_group_numbers) && row.target_group_numbers.length
          ? row.target_group_numbers
          : [row.group_number],
        row.group_count
      );
    const rowSubjectName = cleanText(
      (subject && (subject.subject_name || subject.title || subject.name))
      || row.subject_title
      || row.template_name,
      160
    );
    const rowGroupCount = Math.max(1, Number((subject && subject.group_count) || row.group_count || 0) || 1);
    const rowDefaultGroup = Math.max(1, Number((subject && subject.default_group) || row.default_group || 0) || 1);
    const groupNumbers = activityType === 'lecture'
      ? [1]
      : (targetGroupNumbers.length ? targetGroupNumbers : [Math.max(1, Number(row.group_number || 0) || rowDefaultGroup)]);

    groupNumbers.forEach((groupNumber) => {
      scheduleRows.push({
        schedule_entry_id: Number(row.schedule_entry_id || 0),
        group_subject_id: Number(row.group_subject_id || 0),
        group_subject_activity_id: Number(row.group_subject_activity_id || 0),
        subject_id: legacySubjectId,
        legacy_subject_id: legacySubjectId,
        subject_name: rowSubjectName,
        subject_title: rowSubjectName,
        target_group_numbers: activityType === 'lecture' ? [] : targetGroupNumbers,
        group_number: Math.max(1, Number(groupNumber || 0) || 1),
        group_label: buildScheduleGroupLabel(activityType === 'lecture', activityType === 'lecture' ? [] : [Math.max(1, Number(groupNumber || 0) || 1)]),
        day_of_week: cleanText(row.day_of_week, 20),
        class_number: Math.max(1, Number(row.class_number || 0) || 1),
        week_number: Math.max(1, Number(row.week_number || 0) || 1),
        lesson_type: activityType,
        activity_type: activityType,
        is_general: normalizeBoolean((subject && subject.is_general) || row.is_general, true),
        group_count: rowGroupCount,
        default_group: rowDefaultGroup,
        compat_homework_enabled: Boolean(compatCourseId && compatSemesterId),
        mapping_state: 'mapped',
        course_id: compatCourseId,
        owner_course_id: compatCourseId,
        course_name: cleanText(courseState.scope.legacy_course_name, 160),
        term_id: Number(courseState.term.id || 0),
        legacy_semester_id: compatSemesterId,
      });
    });
  });

  return {
    ...courseState,
    scheduleRows: scheduleRows.sort((a, b) => {
      const byDay = String(a.day_of_week || '').localeCompare(String(b.day_of_week || ''));
      if (byDay !== 0) return byDay;
      const byClass = Number(a.class_number || 0) - Number(b.class_number || 0);
      if (byClass !== 0) return byClass;
      return Number(a.group_number || 0) - Number(b.group_number || 0);
    }),
    projectionIssues: finalizeProjectionIssues({
      ...courseState.projectionIssues,
      unmapped_schedule_entries: unmappedScheduleEntries,
    }),
  };
}

module.exports = {
  buildEmptyProjectionIssues,
  finalizeProjectionIssues,
  getCourseScopeByLegacyCourse,
  getActiveTermForGroup,
  loadCourseProjectionState,
  loadCourseSubjectScope,
  loadCourseScheduleRows,
  listTeacherAssignedSubjectRows,
  listTeacherAssignedSubjectRowsByUsers,
  listCourseUsersByLegacyCourse,
};
