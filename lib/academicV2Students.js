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

function normalizeDayOfWeek(value, fallback = 'Monday') {
  const normalized = cleanText(value, 40).toLowerCase();
  const labelByKey = {
    monday: 'Monday',
    tuesday: 'Tuesday',
    wednesday: 'Wednesday',
    thursday: 'Thursday',
    friday: 'Friday',
    saturday: 'Saturday',
    sunday: 'Sunday',
  };
  return labelByKey[normalized] || labelByKey[String(fallback || '').trim().toLowerCase()] || 'Monday';
}

function normalizeSortOrder(value, fallback = 0) {
  const normalized = Number(value || 0);
  if (Number.isInteger(normalized)) {
    return normalized;
  }
  return Number.isInteger(Number(fallback || 0)) ? Number(fallback || 0) : 0;
}

function buildEmptyProjectionIssues() {
  return {
    has_issues: false,
    missing_scope: false,
    missing_active_term: false,
    missing_legacy_course: false,
    missing_legacy_semester: false,
    unmapped_subjects: [],
    unmapped_schedule_entries: [],
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
  normalized.unmapped_schedule_entries = Array.isArray(normalized.unmapped_schedule_entries)
    ? normalized.unmapped_schedule_entries
    : [];
  normalized.has_issues = Boolean(
    normalized.missing_scope
    || normalized.missing_active_term
    || normalized.missing_legacy_course
    || normalized.missing_legacy_semester
    || normalized.unmapped_subjects.length
    || normalized.unmapped_schedule_entries.length
  );
  return normalized;
}

function buildGroupLabel(hasAllGroups, groupNumbers = []) {
  if (hasAllGroups) {
    return 'Усі групи';
  }
  if (groupNumbers.length === 1) {
    return `Група ${groupNumbers[0]}`;
  }
  if (groupNumbers.length > 1) {
    return `Групи ${groupNumbers.join(', ')}`;
  }
  return 'Без групи';
}

function sortScheduleRows(a, b) {
  const dayOrder = {
    Monday: 1,
    Tuesday: 2,
    Wednesday: 3,
    Thursday: 4,
    Friday: 5,
    Saturday: 6,
    Sunday: 7,
  };
  const dayDiff = Number(dayOrder[a.day_of_week] || 99) - Number(dayOrder[b.day_of_week] || 99);
  if (dayDiff !== 0) return dayDiff;
  const classDiff = Number(a.class_number || 0) - Number(b.class_number || 0);
  if (classDiff !== 0) return classDiff;
  const groupDiff = Number(a.group_number || 0) - Number(b.group_number || 0);
  if (groupDiff !== 0) return groupDiff;
  return Number(a.schedule_entry_id || 0) - Number(b.schedule_entry_id || 0);
}

async function loadUserRow(store, userOrId) {
  if (userOrId && typeof userOrId === 'object') {
    return {
      id: normalizePositiveInt(userOrId.id),
      group_id: normalizePositiveInt(userOrId.group_id),
      study_context_id: normalizePositiveInt(userOrId.study_context_id),
      course_id: normalizePositiveInt(userOrId.course_id),
      schedule_group: cleanText(userOrId.schedule_group, 40),
      admission_id: normalizePositiveInt(userOrId.admission_id),
      study_program_id: normalizePositiveInt(userOrId.study_program_id),
      study_track: cleanText(userOrId.study_track, 40),
    };
  }
  const userId = normalizePositiveInt(userOrId);
  if (!userId || !store || typeof store.get !== 'function') {
    return null;
  }
  const row = await store.get(
    `
      SELECT
        id,
        group_id,
        study_context_id,
        course_id,
        schedule_group,
        admission_id,
        study_program_id,
        study_track
      FROM users
      WHERE id = ?
      LIMIT 1
    `,
    [userId]
  );
  return row || null;
}

const GROUP_SCOPE_SELECT = `
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
  WHERE g.is_active = TRUE
    AND COALESCE(c.is_active, TRUE) = TRUE
    AND COALESCE(p.is_active, TRUE) = TRUE
`;

function mapScopeRow(row, resolvedVia = '') {
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
    admission_year: Number(row.admission_year || 0),
    legacy_admission_id: normalizePositiveInt(row.legacy_admission_id),
    program_id: Number(row.program_id || 0),
    program_code: cleanText(row.program_code, 80),
    program_name: cleanText(row.program_name, 160),
    track_key: cleanText(row.track_key, 20) || 'bachelor',
    resolved_via: cleanText(resolvedVia, 40),
  };
}

async function getGroupScopeById(store, groupId) {
  const normalizedGroupId = normalizePositiveInt(groupId);
  if (!normalizedGroupId) return null;
  const row = await store.get(
    `
      ${GROUP_SCOPE_SELECT}
        AND g.id = ?
      LIMIT 1
    `,
    [normalizedGroupId]
  );
  return mapScopeRow(row, 'group_id');
}

async function getGroupScopeByLegacyStudyContext(store, studyContextId) {
  const normalizedStudyContextId = normalizePositiveInt(studyContextId);
  if (!normalizedStudyContextId) return null;
  const row = await store.get(
    `
      ${GROUP_SCOPE_SELECT}
        AND g.legacy_study_context_id = ?
      ORDER BY c.admission_year DESC, g.stage_number ASC, g.id ASC
      LIMIT 1
    `,
    [normalizedStudyContextId]
  );
  return mapScopeRow(row, 'study_context_id');
}

async function getGroupScopeByLegacyCourse(store, courseId) {
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedCourseId) return null;
  const row = await store.get(
    `
      ${GROUP_SCOPE_SELECT}
        AND g.legacy_course_id = ?
      ORDER BY c.admission_year DESC, g.stage_number ASC, g.id ASC
      LIMIT 1
    `,
    [normalizedCourseId]
  );
  return mapScopeRow(row, 'course_id');
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

async function getActiveGroupTerm(store, groupId) {
  const normalizedGroupId = normalizePositiveInt(groupId);
  if (!normalizedGroupId) return null;
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
        AND COALESCE(is_archived, FALSE) = FALSE
      ORDER BY is_active DESC, term_number ASC, id ASC
      LIMIT 1
    `,
    [normalizedGroupId]
  );
  return mapTermRow(row);
}

async function resolveStudentAcademicScope(store, userOrId) {
  const user = await loadUserRow(store, userOrId);
  if (!user) {
    return {
      user: null,
      scope: null,
      term: null,
      projectionIssues: finalizeProjectionIssues({ missing_scope: true }),
    };
  }

  let scope = await getGroupScopeById(store, user.group_id);
  if (!scope) {
    scope = await getGroupScopeByLegacyStudyContext(store, user.study_context_id);
  }
  if (!scope) {
    scope = await getGroupScopeByLegacyCourse(store, user.course_id);
  }

  const term = scope ? await getActiveGroupTerm(store, scope.group_id) : null;
  const projectionIssues = finalizeProjectionIssues({
    missing_scope: !scope,
    missing_active_term: Boolean(scope) && !term,
    missing_legacy_course: Boolean(scope) && !scope.legacy_course_id,
    missing_legacy_semester: Boolean(term) && !term.legacy_semester_id,
  });

  return {
    user,
    scope,
    term,
    projectionIssues,
  };
}

async function listScopedGroupSubjectRows(store, groupId, termId = null) {
  const normalizedGroupId = normalizePositiveInt(groupId);
  if (!normalizedGroupId || !store || typeof store.all !== 'function') {
    return [];
  }
  const rows = await store.all(
    `
      SELECT
        gs.id AS group_subject_id,
        gs.subject_template_id,
        gs.title AS subject_title,
        gs.group_count,
        gs.default_group,
        gs.is_visible,
        gs.is_required,
        gs.is_general,
        gs.show_in_teamwork,
        gs.sort_order,
        gs.legacy_subject_id,
        st.name AS template_name
      FROM academic_v2_group_subjects gs
      JOIN academic_v2_subject_templates st ON st.id = gs.subject_template_id
      WHERE gs.group_id = ?
        AND gs.is_visible = TRUE
        AND (
          ? IS NULL
          OR NOT EXISTS (
            SELECT 1
            FROM academic_v2_group_subject_terms gst
            WHERE gst.group_subject_id = gs.id
          )
          OR EXISTS (
            SELECT 1
            FROM academic_v2_group_subject_terms gst
            WHERE gst.group_subject_id = gs.id
              AND gst.term_id = ?
          )
        )
      ORDER BY gs.sort_order ASC, gs.title ASC, gs.id ASC
    `,
    [normalizedGroupId, normalizePositiveInt(termId), normalizePositiveInt(termId)]
  );
  return Array.isArray(rows) ? rows : [];
}

async function loadSubjectSelectionState(store, userId, subjectIds = []) {
  const normalizedUserId = normalizePositiveInt(userId);
  const normalizedSubjectIds = Array.from(new Set(
    (Array.isArray(subjectIds) ? subjectIds : [subjectIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const selectedGroupBySubjectId = new Map();
  const optedOutSubjectIds = new Set();

  if (!normalizedUserId || !normalizedSubjectIds.length) {
    return { selectedGroupBySubjectId, optedOutSubjectIds };
  }

  const [selectionRows, optoutRows] = await Promise.all([
    store.all(
      `
        SELECT subject_id, group_number
        FROM student_groups
        WHERE student_id = ?
          AND subject_id = ANY(?::int[])
      `,
      [normalizedUserId, normalizedSubjectIds]
    ),
    store.all(
      `
        SELECT subject_id
        FROM user_subject_optouts
        WHERE user_id = ?
          AND subject_id = ANY(?::int[])
      `,
      [normalizedUserId, normalizedSubjectIds]
    ),
  ]);

  (selectionRows || []).forEach((row) => {
    const subjectId = normalizePositiveInt(row.subject_id);
    const groupNumber = normalizePositiveInt(row.group_number);
    if (!subjectId || !groupNumber || selectedGroupBySubjectId.has(subjectId)) {
      return;
    }
    selectedGroupBySubjectId.set(subjectId, groupNumber);
  });

  (optoutRows || []).forEach((row) => {
    const subjectId = normalizePositiveInt(row.subject_id);
    if (subjectId) {
      optedOutSubjectIds.add(subjectId);
    }
  });

  return { selectedGroupBySubjectId, optedOutSubjectIds };
}

function mapSubjectRow(row, scope, term, selectionState) {
  const subjectId = normalizePositiveInt(row.legacy_subject_id);
  const groupCount = Math.max(1, Number(row.group_count || 0) || 1);
  const defaultGroup = Math.max(1, Math.min(groupCount, Number(row.default_group || 0) || 1));
  const rawSelectedGroup = subjectId ? normalizePositiveInt(selectionState.selectedGroupBySubjectId.get(subjectId)) : null;
  const selectedGroup = rawSelectedGroup && rawSelectedGroup <= groupCount ? rawSelectedGroup : null;
  const optedOut = Boolean(subjectId && selectionState.optedOutSubjectIds.has(subjectId));
  const isRequired = normalizeBoolean(row.is_required, true);
  const isGeneral = normalizeBoolean(row.is_general, true);
  const effectiveSelectedGroup = !optedOut && selectedGroup
    ? selectedGroup
    : (!optedOut && isRequired && groupCount === 1 ? defaultGroup : null);
  const groupNumbers = !isGeneral && effectiveSelectedGroup ? [effectiveSelectedGroup] : [];
  return {
    id: subjectId,
    subject_id: subjectId,
    legacy_subject_id: subjectId,
    group_subject_id: Number(row.group_subject_id || 0),
    subject_template_id: Number(row.subject_template_id || 0),
    name: cleanText(row.subject_title || row.template_name, 160),
    subject_name: cleanText(row.subject_title || row.template_name, 160),
    subject_title: cleanText(row.subject_title || row.template_name, 160),
    template_name: cleanText(row.template_name, 160),
    group_id: Number(scope.group_id || 0),
    group_label: buildGroupLabel(isGeneral, groupNumbers),
    academic_group_label: cleanText(scope.group_label, 160),
    course_id: normalizePositiveInt(scope.legacy_course_id),
    owner_course_id: normalizePositiveInt(scope.legacy_course_id),
    course_name: cleanText(scope.legacy_course_name, 160),
    term_id: normalizePositiveInt(term && term.id),
    legacy_semester_id: normalizePositiveInt(term && term.legacy_semester_id),
    group_count: groupCount,
    default_group: defaultGroup,
    is_required: isRequired,
    is_general: isGeneral,
    is_visible: normalizeBoolean(row.is_visible, true),
    show_in_teamwork: normalizeBoolean(row.show_in_teamwork, true),
    sort_order: normalizeSortOrder(row.sort_order, 0),
    selected_group: effectiveSelectedGroup,
    opted_out: optedOut,
    is_selected: !optedOut && Boolean(effectiveSelectedGroup),
    has_all_groups: isGeneral,
    group_numbers: groupNumbers,
    available_group_numbers: Array.from({ length: groupCount }, (_value, index) => index + 1),
  };
}

async function loadStudentSubjectCatalog(store, userOrId, options = {}) {
  const selectedOnly = options.selectedOnly === true;
  const scopeState = await resolveStudentAcademicScope(store, userOrId);
  const baseIssues = finalizeProjectionIssues(scopeState.projectionIssues);
  if (!scopeState.scope) {
    return {
      ...scopeState,
      total_visible_subjects: 0,
      mapped_visible_subjects: 0,
      allSubjects: [],
      subjects: [],
      projectionIssues: baseIssues,
    };
  }

  const scopedRows = await listScopedGroupSubjectRows(
    store,
    scopeState.scope.group_id,
    scopeState.term ? scopeState.term.id : null
  );
  const selectionState = await loadSubjectSelectionState(
    store,
    scopeState.user && scopeState.user.id,
    scopedRows.map((row) => row.legacy_subject_id)
  );

  const mappedSubjects = [];
  const unmappedSubjects = [];
  (scopedRows || []).forEach((row) => {
    const subjectId = normalizePositiveInt(row.legacy_subject_id);
    if (!subjectId) {
      unmappedSubjects.push({
        group_subject_id: Number(row.group_subject_id || 0),
        subject_title: cleanText(row.subject_title || row.template_name, 160),
      });
      return;
    }
    mappedSubjects.push(mapSubjectRow(row, scopeState.scope, scopeState.term, selectionState));
  });

  const projectionIssues = finalizeProjectionIssues({
    ...baseIssues,
    unmapped_subjects: unmappedSubjects,
  });

  return {
    ...scopeState,
    total_visible_subjects: (scopedRows || []).length,
    mapped_visible_subjects: mappedSubjects.length,
    allSubjects: mappedSubjects,
    subjects: selectedOnly
      ? mappedSubjects.filter((subject) => subject.is_selected)
      : mappedSubjects,
    projectionIssues,
  };
}

async function loadStudentScheduleData(store, userOrId, options = {}) {
  const normalizedWeekNumber = Math.max(1, Number(options.weekNumber || 0) || 1);
  const subjectState = await loadStudentSubjectCatalog(store, userOrId, { selectedOnly: true });
  if (!subjectState.scope || !subjectState.term) {
    return {
      ...subjectState,
      scheduleRows: [],
      projectionIssues: finalizeProjectionIssues(subjectState.projectionIssues),
    };
  }

  const rows = await store.all(
    `
      SELECT
        se.id AS schedule_entry_id,
        se.group_subject_id,
        se.group_number,
        se.day_of_week,
        se.class_number,
        se.week_number,
        se.lesson_type,
        gs.title AS subject_title,
        gs.legacy_subject_id,
        gs.is_general,
        gs.group_count,
        gs.default_group,
        st.name AS template_name
      FROM academic_v2_schedule_entries se
      JOIN academic_v2_group_subjects gs ON gs.id = se.group_subject_id
      JOIN academic_v2_subject_templates st ON st.id = gs.subject_template_id
      WHERE gs.group_id = ?
        AND se.term_id = ?
        AND se.week_number = ?
        AND gs.is_visible = TRUE
      ORDER BY se.day_of_week ASC, se.class_number ASC, se.group_number ASC, se.id ASC
    `,
    [subjectState.scope.group_id, subjectState.term.id, normalizedWeekNumber]
  );

  const subjectById = new Map(
    (subjectState.subjects || []).map((subject) => [Number(subject.subject_id || 0), subject])
  );
  const scheduleRows = [];
  const unmappedScheduleEntries = [];

  (rows || []).forEach((row) => {
    const legacySubjectId = normalizePositiveInt(row.legacy_subject_id);
    const subject = legacySubjectId ? subjectById.get(legacySubjectId) : null;
    if (!legacySubjectId || !subject || !normalizePositiveInt(subjectState.scope.legacy_course_id)) {
      unmappedScheduleEntries.push({
        schedule_entry_id: Number(row.schedule_entry_id || 0),
        group_subject_id: Number(row.group_subject_id || 0),
        subject_title: cleanText(row.subject_title || row.template_name, 160),
      });
      return;
    }

    const rowGroupNumber = Math.max(1, Number(row.group_number || 0) || subject.selected_group || subject.default_group || 1);
    const selectedGroup = Math.max(1, Number(subject.selected_group || 0) || subject.default_group || 1);
    const lessonType = cleanText(row.lesson_type, 40).toLowerCase() || 'lecture';
    if (lessonType !== 'lecture' && rowGroupNumber !== selectedGroup) {
      return;
    }

    scheduleRows.push({
      schedule_entry_id: Number(row.schedule_entry_id || 0),
      group_subject_id: Number(row.group_subject_id || 0),
      subject_id: legacySubjectId,
      legacy_subject_id: legacySubjectId,
      subject_name: cleanText(row.subject_title || row.template_name, 160),
      subject_title: cleanText(row.subject_title || row.template_name, 160),
      group_number: rowGroupNumber,
      group_label: normalizeBoolean(row.is_general, true) ? 'Усі групи' : `Група ${rowGroupNumber}`,
      day_of_week: normalizeDayOfWeek(row.day_of_week, 'Monday'),
      class_number: Math.max(1, Number(row.class_number || 0) || 1),
      week_number: Math.max(1, Number(row.week_number || 0) || 1),
      lesson_type: lessonType,
      is_general: normalizeBoolean(row.is_general, true),
      group_count: Math.max(1, Number(row.group_count || 0) || 1),
      default_group: Math.max(1, Number(row.default_group || 0) || 1),
      course_id: normalizePositiveInt(subjectState.scope.legacy_course_id),
      owner_course_id: normalizePositiveInt(subjectState.scope.legacy_course_id),
      course_name: cleanText(subjectState.scope.legacy_course_name, 160),
      term_id: Number(subjectState.term.id || 0),
      legacy_semester_id: normalizePositiveInt(subjectState.term.legacy_semester_id),
    });
  });

  return {
    ...subjectState,
    scheduleRows: scheduleRows.sort(sortScheduleRows),
    projectionIssues: finalizeProjectionIssues({
      ...subjectState.projectionIssues,
      unmapped_schedule_entries: unmappedScheduleEntries,
    }),
  };
}

module.exports = {
  resolveStudentAcademicScope,
  loadStudentSubjectCatalog,
  loadStudentScheduleData,
};
