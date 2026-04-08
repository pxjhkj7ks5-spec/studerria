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

function sqlTruthyExpr(expression, nullDefault = false) {
  const fallback = nullDefault ? '1' : '0';
  return `COALESCE(NULLIF(LOWER(TRIM(CAST(${expression} AS TEXT))), ''), '${fallback}') IN ('1', 'true', 't', 'yes', 'on')`;
}

function sqlFalsyExpr(expression, nullDefault = false) {
  const fallback = nullDefault ? '1' : '0';
  return `COALESCE(NULLIF(LOWER(TRIM(CAST(${expression} AS TEXT))), ''), '${fallback}') IN ('0', 'false', 'f', 'no', 'off')`;
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

function resolveTermWeeksCount(termNumber) {
  const normalized = Math.max(1, Number(termNumber || 0) || 1);
  if (normalized === 3) {
    return 7;
  }
  if (normalized === 1 || normalized === 2) {
    return 15;
  }
  return 15;
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

function resolveScheduleEntryGroupScope(row = {}, fallbackGroupCount = 1, fallbackDefaultGroup = 1) {
  const rawTargetGroups = normalizeGroupNumberArray(row.target_group_numbers || []);
  const effectiveGroupCount = Math.min(3, Math.max(
    1,
    Number(fallbackGroupCount || 0) || 1,
    Number(fallbackDefaultGroup || 0) || 1,
    Number(row.group_count || 0) || 1,
    Number(row.default_group || 0) || 1,
    Number(row.group_number || 0) || 1,
    ...rawTargetGroups
  ));
  const effectiveDefaultGroup = Math.min(effectiveGroupCount, Math.max(
    1,
    Number(fallbackDefaultGroup || 0) || 1,
    Number(row.default_group || 0) || 1,
    Number(row.group_number || 0) || 1
  ));
  return {
    groupCount: effectiveGroupCount,
    defaultGroup: effectiveDefaultGroup,
  };
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
  WHERE ${sqlTruthyExpr('g.is_active', true)}
    AND ${sqlTruthyExpr('c.is_active', true)}
    AND ${sqlTruthyExpr('p.is_active', true)}
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
    weeks_count: resolveTermWeeksCount(row.term_number),
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
        AND ${sqlFalsyExpr('is_archived', false)}
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

async function listScopedGroupSubjectRows(store, groupId, termId = null, options = {}) {
  const normalizedGroupId = normalizePositiveInt(groupId);
  const normalizedTermId = normalizePositiveInt(termId);
  const includeHidden = options && options.includeHidden === true;
  if (!normalizedGroupId || !store || typeof store.all !== 'function') {
    return [];
  }
  const params = [normalizedGroupId];
  const scopedTermSql = normalizedTermId
    ? `
        AND (
          NOT EXISTS (
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
      `
    : '';
  if (normalizedTermId) {
    params.push(normalizedTermId);
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
        ${includeHidden ? '' : `AND ${sqlTruthyExpr('gs.is_visible', true)}`}
        ${scopedTermSql}
      ORDER BY gs.sort_order ASC, gs.title ASC, gs.id ASC
    `,
    params
  );
  return Array.isArray(rows) ? rows : [];
}

async function listBachelorStageTemplateSubjectRows(store, programId, stageNumber) {
  const normalizedProgramId = normalizePositiveInt(programId);
  const normalizedStageNumber = normalizePositiveInt(stageNumber);
  if (!normalizedProgramId || !normalizedStageNumber || !store || typeof store.all !== 'function') {
    return [];
  }
  const rows = await store.all(
    `
      SELECT
        stage_subject.id AS stage_subject_template_id,
        stage_subject.subject_template_id,
        stage_subject.title AS subject_title,
        stage_subject.group_count,
        stage_subject.default_group,
        stage_subject.is_visible,
        stage_subject.is_required,
        stage_subject.is_general,
        stage_subject.show_in_teamwork,
        stage_subject.sort_order,
        st.name AS template_name,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT stage_term.term_number), NULL),
          ARRAY[]::int[]
        ) AS term_numbers
      FROM academic_v2_program_stage_subject_templates stage_subject
      JOIN academic_v2_program_stage_templates stage_template ON stage_template.id = stage_subject.stage_template_id
      JOIN academic_v2_subject_templates st ON st.id = stage_subject.subject_template_id
      LEFT JOIN academic_v2_program_stage_subject_terms stage_subject_term
        ON stage_subject_term.stage_subject_template_id = stage_subject.id
      LEFT JOIN academic_v2_program_stage_term_templates stage_term
        ON stage_term.id = stage_subject_term.stage_term_template_id
      WHERE stage_template.program_id = ?
        AND stage_template.stage_number = ?
      GROUP BY stage_subject.id, st.name
      ORDER BY stage_subject.sort_order ASC, COALESCE(NULLIF(stage_subject.title, ''), st.name) ASC, stage_subject.id ASC
    `,
    [normalizedProgramId, normalizedStageNumber]
  );
  return Array.isArray(rows) ? rows : [];
}

async function overlayBachelorCatalogSubjectRows(store, rows = [], options = {}) {
  const sourceRows = Array.isArray(rows) ? rows : [];
  const normalizedProgramId = normalizePositiveInt(options.programId || options.program_id);
  const normalizedStageNumber = normalizePositiveInt(options.stageNumber || options.stage_number);
  const normalizedTermNumber = normalizePositiveInt(options.termNumber || options.term_number);
  if (!sourceRows.length || !normalizedProgramId || !normalizedStageNumber) {
    return sourceRows;
  }

  const stageRows = await listBachelorStageTemplateSubjectRows(store, normalizedProgramId, normalizedStageNumber);
  if (!stageRows.length) {
    return sourceRows;
  }

  const stageRowByTemplateId = new Map(
    stageRows
      .map((row) => [normalizePositiveInt(row && row.subject_template_id), row])
      .filter(([subjectTemplateId]) => subjectTemplateId)
  );

  return sourceRows
    .map((row) => {
      const subjectTemplateId = normalizePositiveInt(row && row.subject_template_id);
      const stageRow = subjectTemplateId ? stageRowByTemplateId.get(subjectTemplateId) : null;
      if (!stageRow) {
        return null;
      }

      const stageTermNumbers = Array.isArray(stageRow.term_numbers)
        ? stageRow.term_numbers
          .map((value) => normalizePositiveInt(value))
          .filter((value) => value === 1 || value === 2 || value === 3)
        : [];
      const allowedByTerm = stageTermNumbers.length > 0
        && (!normalizedTermNumber || stageTermNumbers.includes(normalizedTermNumber));
      const isVisible = normalizeBoolean(stageRow.is_visible, true);
      if (!allowedByTerm || !isVisible) {
        return null;
      }

      const mergedGroupCount = Math.max(1, Math.min(3, Number(stageRow.group_count || 0) || 1));
      const mergedDefaultGroup = Math.max(1, Math.min(mergedGroupCount, Number(stageRow.default_group || 0) || 1));
      return {
        ...row,
        subject_title: cleanText(stageRow.subject_title || stageRow.template_name, 160),
        group_count: mergedGroupCount,
        default_group: mergedDefaultGroup,
        is_visible: normalizeBoolean(stageRow.is_visible, true),
        is_required: normalizeBoolean(stageRow.is_required, true),
        is_general: normalizeBoolean(stageRow.is_general, true),
        show_in_teamwork: normalizeBoolean(stageRow.show_in_teamwork, true),
        sort_order: normalizeSortOrder(stageRow.sort_order, 0),
        template_name: cleanText(stageRow.template_name, 160) || cleanText(row.template_name, 160),
      };
    })
    .filter(Boolean)
    .sort((left, right) => {
      const sortDiff = normalizeSortOrder(left && left.sort_order, 0) - normalizeSortOrder(right && right.sort_order, 0);
      if (sortDiff !== 0) {
        return sortDiff;
      }
      return cleanText(left && left.subject_title, 160).localeCompare(cleanText(right && right.subject_title, 160), 'uk', {
        sensitivity: 'base',
        numeric: true,
      });
    });
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

  const isBachelorScope = scopeState.scope && String(scopeState.scope.track_key || '') === 'bachelor';
  let scopedRows = await listScopedGroupSubjectRows(
    store,
    scopeState.scope.group_id,
    isBachelorScope
      ? null
      : (scopeState.term ? scopeState.term.id : null),
    {
      includeHidden: isBachelorScope,
    }
  );
  if (isBachelorScope) {
    scopedRows = await overlayBachelorCatalogSubjectRows(store, scopedRows, {
      programId: scopeState.scope.program_id,
      stageNumber: scopeState.scope.stage_number,
      termNumber: scopeState.term ? scopeState.term.term_number : null,
    });
  }
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
  const debugEnabled = options.debug === true;
  const normalizedWeekNumber = Math.max(1, Number(options.weekNumber || 0) || 1);
  const subjectState = await loadStudentSubjectCatalog(store, userOrId, { selectedOnly: true });
  const debugSubjectCatalog = {
    all_visible_subjects: Array.isArray(subjectState.allSubjects)
      ? subjectState.allSubjects.map((subject) => ({
        subject_id: normalizePositiveInt(subject.subject_id),
        group_subject_id: Number(subject.group_subject_id || 0),
        subject_title: cleanText(subject.subject_title || subject.subject_name || subject.name, 160),
        is_selected: Boolean(subject.is_selected),
        is_required: normalizeBoolean(subject.is_required, true),
        is_general: normalizeBoolean(subject.is_general, true),
        selected_group: normalizePositiveInt(subject.selected_group),
      }))
      : [],
    selected_subjects: Array.isArray(subjectState.subjects)
      ? subjectState.subjects.map((subject) => ({
        subject_id: normalizePositiveInt(subject.subject_id),
        group_subject_id: Number(subject.group_subject_id || 0),
        subject_title: cleanText(subject.subject_title || subject.subject_name || subject.name, 160),
        selected_group: normalizePositiveInt(subject.selected_group),
        is_required: normalizeBoolean(subject.is_required, true),
        is_general: normalizeBoolean(subject.is_general, true),
      }))
      : [],
    unmapped_subjects: Array.isArray(subjectState.projectionIssues && subjectState.projectionIssues.unmapped_subjects)
      ? subjectState.projectionIssues.unmapped_subjects.map((subject) => ({
        group_subject_id: Number(subject && subject.group_subject_id || 0),
        subject_title: cleanText(subject && subject.subject_title, 160),
      }))
      : [],
  };
  const buildDebugPayload = (payload = {}) => {
    if (!debugEnabled) {
      return null;
    }
    const rowDecisions = Array.isArray(payload.row_decisions) ? payload.row_decisions : [];
    return {
      enabled: true,
      resolved_scope: {
        user_group_id: normalizePositiveInt(subjectState.user && subjectState.user.group_id),
        user_study_context_id: normalizePositiveInt(subjectState.user && subjectState.user.study_context_id),
        user_course_id: normalizePositiveInt(subjectState.user && subjectState.user.course_id),
        academic_group_id: normalizePositiveInt(subjectState.scope && subjectState.scope.group_id),
        academic_group_label: cleanText(subjectState.scope && subjectState.scope.group_label, 160),
        academic_group_code: cleanText(subjectState.scope && subjectState.scope.group_code, 80),
        legacy_course_id: normalizePositiveInt(subjectState.scope && subjectState.scope.legacy_course_id),
        legacy_course_name: cleanText(subjectState.scope && subjectState.scope.legacy_course_name, 160),
        resolved_via: cleanText(subjectState.scope && subjectState.scope.resolved_via, 40),
      },
      resolved_term: subjectState.term ? {
        term_id: Number(subjectState.term.id || 0),
        title: cleanText(subjectState.term.title, 160),
        term_number: Math.max(1, Number(subjectState.term.term_number || 0) || 1),
        start_date: cleanText(subjectState.term.start_date, 20),
        weeks_count: resolveTermWeeksCount(subjectState.term.term_number),
        legacy_semester_id: normalizePositiveInt(subjectState.term.legacy_semester_id),
      } : null,
      selected_week: normalizedWeekNumber,
      subject_catalog: debugSubjectCatalog,
      raw_schedule_rows: Array.isArray(payload.raw_schedule_rows) ? payload.raw_schedule_rows : [],
      row_decisions: rowDecisions,
      summary: {
        raw_rows_total: Array.isArray(payload.raw_schedule_rows) ? payload.raw_schedule_rows.length : 0,
        included_rows_total: rowDecisions.filter((row) => row && row.included === true).length,
        dropped_rows_total: rowDecisions.filter((row) => row && row.included !== true).length,
        note: 'Admin Pathways focus is not used here. Student schedule resolves only through resolveStudentAcademicScope(user) and its active Academic V2 term.',
      },
    };
  };
  if (!subjectState.scope || !subjectState.term) {
    const result = {
      ...subjectState,
      scheduleRows: [],
      projectionIssues: finalizeProjectionIssues(subjectState.projectionIssues),
    };
    if (debugEnabled) {
      result.debug = buildDebugPayload({
        raw_schedule_rows: [],
        row_decisions: [
          {
            included: false,
            reason_code: 'dropped_scope_without_term',
            schedule_entry_id: 0,
            group_subject_id: 0,
            group_subject_activity_id: 0,
            legacy_subject_id: null,
            subject_title: '',
            activity_type: '',
            week_number: normalizedWeekNumber,
            day_of_week: '',
            class_number: 0,
            mapping_state: 'unmapped',
            compat_homework_enabled: false,
          },
        ],
      });
    }
    return result;
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
        gs.title AS subject_title,
        gs.legacy_subject_id,
        gs.is_visible,
        gs.is_required,
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
      ORDER BY se.day_of_week ASC, se.class_number ASC, COALESCE(se.group_number, 1) ASC, se.id ASC
    `,
    [subjectState.scope.group_id, subjectState.term.id, normalizedWeekNumber]
  );

  const selectedSubjectById = new Map(
    (subjectState.subjects || []).map((subject) => [Number(subject.subject_id || 0), subject])
  );
  const visibleSubjectById = new Map(
    (subjectState.allSubjects || []).map((subject) => [Number(subject.subject_id || 0), subject])
  );
  const scheduleRows = [];
  const unmappedScheduleEntries = [];
  const rawScheduleRows = [];
  const rowDecisions = [];
  const compatCourseId = normalizePositiveInt(subjectState.scope.legacy_course_id);
  const compatSemesterId = normalizePositiveInt(subjectState.term.legacy_semester_id);

  (rows || []).forEach((row) => {
    const scheduleEntryId = Number(row.schedule_entry_id || 0);
    const groupSubjectId = Number(row.group_subject_id || 0);
    const groupSubjectActivityId = Number(row.group_subject_activity_id || 0);
    const legacySubjectId = normalizePositiveInt(row.legacy_subject_id);
    const isVisible = normalizeBoolean(row.is_visible, true);
    const isRequired = normalizeBoolean(row.is_required, true);
    const activityType = cleanText(row.activity_type || row.lesson_type, 40).toLowerCase() || 'lecture';
    const mappingState = legacySubjectId ? 'mapped' : 'unmapped';
    const selectedSubject = legacySubjectId ? selectedSubjectById.get(legacySubjectId) : null;
    const visibleSubject = legacySubjectId ? visibleSubjectById.get(legacySubjectId) : null;
    const fallbackGroupCount = Math.max(
      1,
      Number(
        (selectedSubject && selectedSubject.group_count)
        || (visibleSubject && visibleSubject.group_count)
        || row.group_count
        || 1
      ) || 1
    );
    const fallbackDefaultGroup = Math.max(
      1,
      Number(
        (selectedSubject && selectedSubject.default_group)
        || (visibleSubject && visibleSubject.default_group)
        || row.default_group
        || 1
      ) || 1
    );
    const { groupCount: effectiveGroupCount, defaultGroup: effectiveDefaultGroup } = resolveScheduleEntryGroupScope(
      row,
      fallbackGroupCount,
      fallbackDefaultGroup
    );
    const targetGroupNumbers = activityType === 'lecture'
      ? []
      : normalizeGroupNumberArray(
        Array.isArray(row.target_group_numbers) && row.target_group_numbers.length
          ? row.target_group_numbers
          : [row.group_number],
        effectiveGroupCount
      );

    rawScheduleRows.push({
      schedule_entry_id: scheduleEntryId,
      group_subject_id: groupSubjectId,
      group_subject_activity_id: groupSubjectActivityId,
      legacy_subject_id: legacySubjectId,
      subject_title: cleanText(row.subject_title || row.template_name, 160),
      activity_type: activityType,
      week_number: Math.max(1, Number(row.week_number || 0) || 1),
      day_of_week: normalizeDayOfWeek(row.day_of_week, 'Monday'),
      class_number: Math.max(1, Number(row.class_number || 0) || 1),
      group_number: Math.max(1, Number(row.group_number || 0) || 1),
      target_group_numbers: targetGroupNumbers,
      is_visible: isVisible,
      mapping_state: mappingState,
    });
    const selectedGroup = Math.max(
      1,
      Number(
        (selectedSubject && (selectedSubject.selected_group || selectedSubject.default_group))
        || (visibleSubject && (visibleSubject.selected_group || visibleSubject.default_group))
        || effectiveDefaultGroup
        || 1
      ) || 1
    );
    let included = false;
    let reasonCode = 'dropped_missing_mapping';
    let compatHomeworkEnabled = false;
    let subject = null;

    if (!isVisible) {
      reasonCode = 'dropped_subject_invisible';
    } else if (activityType === 'lecture') {
      if (selectedSubject) {
        included = true;
        reasonCode = 'included_selected_subject';
        compatHomeworkEnabled = Boolean(legacySubjectId && compatCourseId && compatSemesterId);
        subject = selectedSubject;
      } else if (visibleSubject) {
        included = true;
        reasonCode = 'included_lecture_visible_subject';
        compatHomeworkEnabled = Boolean(legacySubjectId && compatCourseId && compatSemesterId);
        subject = visibleSubject;
      } else {
        included = true;
        reasonCode = 'included_lecture_unmapped_subject';
        compatHomeworkEnabled = false;
        subject = {
          selected_group: null,
          default_group: effectiveDefaultGroup,
          is_required: isRequired,
          is_general: normalizeBoolean(row.is_general, true),
          opted_out: false,
          group_count: effectiveGroupCount,
        };
      }
    } else if (!legacySubjectId || !visibleSubject) {
      reasonCode = 'dropped_missing_mapping';
    } else if (!selectedSubject) {
      reasonCode = 'dropped_subject_not_selected';
    } else if (!targetGroupNumbers.includes(selectedGroup)) {
      reasonCode = 'dropped_subgroup_mismatch';
    } else {
      included = true;
      reasonCode = 'included_selected_subject';
      compatHomeworkEnabled = Boolean(legacySubjectId && compatCourseId && compatSemesterId);
      subject = selectedSubject;
    }

    if (!legacySubjectId) {
      unmappedScheduleEntries.push({
        schedule_entry_id: scheduleEntryId,
        group_subject_id: groupSubjectId,
        subject_title: cleanText(row.subject_title || row.template_name, 160),
      });
    }

    rowDecisions.push({
      schedule_entry_id: scheduleEntryId,
      group_subject_id: groupSubjectId,
      group_subject_activity_id: groupSubjectActivityId,
      legacy_subject_id: legacySubjectId,
      subject_title: cleanText(row.subject_title || row.template_name, 160),
      activity_type: activityType,
      week_number: Math.max(1, Number(row.week_number || 0) || 1),
      day_of_week: normalizeDayOfWeek(row.day_of_week, 'Monday'),
      class_number: Math.max(1, Number(row.class_number || 0) || 1),
      group_number: Math.max(1, Number(row.group_number || 0) || 1),
      target_group_numbers: targetGroupNumbers,
      selected_group: selectedSubject ? selectedGroup : null,
      included,
      reason_code: reasonCode,
      mapping_state: mappingState,
      compat_homework_enabled: compatHomeworkEnabled,
    });
    if (!included || !subject) {
      return;
    }

    const rowGroupNumber = activityType === 'lecture'
      ? 1
      : Math.max(
        1,
        Number(
          (targetGroupNumbers.includes(selectedGroup) ? selectedGroup : null)
          || targetGroupNumbers[0]
          || selectedGroup
          || subject.default_group
          || effectiveDefaultGroup
          || 1
        ) || 1
      );
    const displayGroupNumbers = activityType === 'lecture'
      ? normalizeGroupNumberArray(
        selectedGroup ? [selectedGroup] : [],
        effectiveGroupCount
      )
      : targetGroupNumbers;
    const displayHasAllGroups = activityType === 'lecture' && !displayGroupNumbers.length;

    scheduleRows.push({
      schedule_entry_id: scheduleEntryId,
      group_subject_id: groupSubjectId,
      group_subject_activity_id: groupSubjectActivityId,
      subject_id: legacySubjectId || (0 - Math.max(1, groupSubjectId || 1)),
      legacy_subject_id: legacySubjectId,
      subject_name: cleanText(row.subject_title || row.template_name, 160),
      subject_title: cleanText(row.subject_title || row.template_name, 160),
      target_group_numbers: activityType === 'lecture' ? [] : targetGroupNumbers,
      group_number: rowGroupNumber,
      selected_group: selectedGroup,
      group_label: buildGroupLabel(displayHasAllGroups, displayGroupNumbers),
      day_of_week: normalizeDayOfWeek(row.day_of_week, 'Monday'),
      class_number: Math.max(1, Number(row.class_number || 0) || 1),
      week_number: Math.max(1, Number(row.week_number || 0) || 1),
      lesson_type: activityType,
      activity_type: activityType,
      is_general: normalizeBoolean(row.is_general, true),
      compat_homework_enabled: compatHomeworkEnabled,
      mapping_state: mappingState,
      group_count: effectiveGroupCount,
      default_group: effectiveDefaultGroup,
      course_id: compatCourseId,
      owner_course_id: compatCourseId,
      course_name: cleanText(subjectState.scope.legacy_course_name, 160),
      term_id: Number(subjectState.term.id || 0),
      legacy_semester_id: compatSemesterId,
    });
  });

  const result = {
    ...subjectState,
    scheduleRows: scheduleRows.sort(sortScheduleRows),
    projectionIssues: finalizeProjectionIssues({
      ...subjectState.projectionIssues,
      unmapped_schedule_entries: unmappedScheduleEntries,
    }),
  };
  if (debugEnabled) {
    result.debug = buildDebugPayload({
      raw_schedule_rows: rawScheduleRows,
      row_decisions: rowDecisions,
    });
  }
  return result;
}

module.exports = {
  resolveStudentAcademicScope,
  loadStudentSubjectCatalog,
  loadStudentScheduleData,
  overlayBachelorCatalogSubjectRows,
};
