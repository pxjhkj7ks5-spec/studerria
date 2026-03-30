const academicV2StudentHelpers = require('./academicV2Students');

const TRACK_ORDER = {
  bachelor: 0,
  master: 1,
  teacher: 2,
};

const DAY_ORDER = {
  monday: 1,
  tuesday: 2,
  wednesday: 3,
  thursday: 4,
  friday: 5,
  saturday: 6,
  sunday: 7,
};

const ACTIVITY_ORDER = {
  lecture: 10,
  seminar: 20,
  practice: 30,
  lab: 40,
};

function cleanText(value, maxLength = 160) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, Math.max(1, Number(maxLength) || 1));
}

function normalizeTrackKey(value, fallback = 'bachelor') {
  const normalized = String(value || '').trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(TRACK_ORDER, normalized)) {
    return normalized;
  }
  return Object.prototype.hasOwnProperty.call(TRACK_ORDER, String(fallback || '').trim().toLowerCase())
    ? String(fallback || '').trim().toLowerCase()
    : 'bachelor';
}

function normalizeCampusKey(value, fallback = 'kyiv') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'munich') {
    return 'munich';
  }
  if (normalized === 'kyiv') {
    return 'kyiv';
  }
  return fallback === 'munich' ? 'munich' : 'kyiv';
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

function normalizePositiveInt(value, fallback = null) {
  const normalized = Number(value || 0);
  if (Number.isInteger(normalized) && normalized > 0) {
    return normalized;
  }
  const normalizedFallback = Number(fallback || 0);
  return Number.isInteger(normalizedFallback) && normalizedFallback > 0 ? normalizedFallback : null;
}

function normalizeBoolean(value, fallback = false) {
  if (Array.isArray(value)) {
    if (!value.length) {
      return fallback === true;
    }
    return normalizeBoolean(value[value.length - 1], fallback);
  }
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1;
  const normalized = String(value || '').trim().toLowerCase();
  if (['1', 'true', 'on', 'yes'].includes(normalized)) return true;
  if (['0', 'false', 'off', 'no'].includes(normalized)) return false;
  return fallback === true;
}

function normalizeLegacyBinaryFlag(value, fallback = false) {
  return normalizeBoolean(value, fallback) ? 1 : 0;
}

function normalizeSubjectTemplateName(value) {
  return cleanText(value, 160).toLowerCase();
}

function normalizeStageNumber(value, fallback = 1) {
  const normalized = Number(value || 0);
  if (Number.isInteger(normalized) && normalized > 0) {
    return normalized;
  }
  const fallbackValue = Number(fallback || 0);
  return Number.isInteger(fallbackValue) && fallbackValue > 0 ? fallbackValue : 1;
}

function normalizeCourseStageNumber(value, fallback = 1) {
  const normalized = normalizeStageNumber(value, fallback);
  return Math.min(4, Math.max(1, Number(normalized || 1)));
}

function normalizeWeeksCount(value, fallback = 16) {
  const normalized = Number(value || 0);
  if (Number.isInteger(normalized) && normalized > 0) {
    return normalized;
  }
  return Number(fallback || 16) > 0 ? Number(fallback || 16) : 16;
}

function normalizeAcademicV2RenderMessage(rawError) {
  return String(rawError || '')
    .replace(/\s+/g, ' ')
    .trim();
}

function sqlTruthyExpr(expression, nullDefault = false) {
  const fallback = nullDefault ? '1' : '0';
  return `COALESCE(NULLIF(LOWER(TRIM(CAST(${expression} AS TEXT))), ''), '${fallback}') IN ('1', 'true', 't', 'yes', 'on')`;
}

function sqlFalsyExpr(expression, nullDefault = false) {
  const fallback = nullDefault ? '1' : '0';
  return `COALESCE(NULLIF(LOWER(TRIM(CAST(${expression} AS TEXT))), ''), '${fallback}') IN ('0', 'false', 'f', 'no', 'off')`;
}

function normalizeSortOrder(value, fallback = 0) {
  const normalized = Number(value || 0);
  if (Number.isInteger(normalized)) {
    return normalized;
  }
  return Number.isInteger(Number(fallback || 0)) ? Number(fallback || 0) : 0;
}

function normalizeDateString(value, fallback = null) {
  const normalized = cleanText(value, 20);
  if (/^\d{4}-\d{2}-\d{2}$/.test(normalized)) {
    return normalized;
  }
  return fallback;
}

function normalizeIdArray(values = []) {
  return Array.from(new Set(
    (Array.isArray(values) ? values : [values])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
}

function normalizeActivityType(value, fallback = 'lecture') {
  const normalized = cleanText(value, 40).toLowerCase();
  if (Object.prototype.hasOwnProperty.call(ACTIVITY_ORDER, normalized)) {
    return normalized;
  }
  return Object.prototype.hasOwnProperty.call(ACTIVITY_ORDER, String(fallback || '').trim().toLowerCase())
    ? String(fallback || '').trim().toLowerCase()
    : 'lecture';
}

function activityTypeLabel(activityType) {
  const normalized = normalizeActivityType(activityType, 'lecture');
  if (normalized === 'lab') {
    return 'Lab';
  }
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function normalizeGroupNumberArray(values = [], maxGroupCount = null) {
  const normalizedMax = normalizePositiveInt(maxGroupCount);
  return normalizeIdArray(values)
    .filter((value) => !normalizedMax || value <= normalizedMax)
    .sort((a, b) => a - b);
}

function deriveScheduleTargetGroups(activityType, values = [], fallbackGroupNumber = 1, maxGroupCount = null) {
  const normalizedType = normalizeActivityType(activityType, 'lecture');
  if (normalizedType === 'lecture') {
    return [];
  }
  const normalizedGroups = normalizeGroupNumberArray(values, maxGroupCount);
  if (normalizedGroups.length) {
    return normalizedGroups;
  }
  const fallback = normalizePositiveInt(fallbackGroupNumber, 1) || 1;
  if (normalizePositiveInt(maxGroupCount) && fallback > maxGroupCount) {
    return [1];
  }
  return [fallback];
}

function deriveScheduleGroupNumber(activityType, targetGroupNumbers = [], fallbackGroupNumber = 1) {
  const normalizedType = normalizeActivityType(activityType, 'lecture');
  if (normalizedType === 'lecture') {
    return 1;
  }
  const normalizedGroups = normalizeGroupNumberArray(targetGroupNumbers);
  return normalizedGroups[0] || normalizePositiveInt(fallbackGroupNumber, 1) || 1;
}

function buildScheduleTargetGroupLabel(activityType, targetGroupNumbers = []) {
  const normalizedType = normalizeActivityType(activityType, 'lecture');
  if (normalizedType === 'lecture') {
    return 'All groups';
  }
  const normalizedGroups = normalizeGroupNumberArray(targetGroupNumbers);
  if (!normalizedGroups.length) {
    return 'By subgroup';
  }
  return normalizedGroups.length === 1
    ? `Group ${normalizedGroups[0]}`
    : `Groups ${normalizedGroups.join(', ')}`;
}

function resolveSubjectActivityPresetTypes(presetKey) {
  const normalizedPreset = cleanText(presetKey, 80).toLowerCase();
  if (normalizedPreset === 'lecture_practice') {
    return ['lecture', 'practice'];
  }
  if (normalizedPreset === 'lecture_seminar_lab') {
    return ['lecture', 'seminar', 'lab'];
  }
  return ['lecture', 'seminar'];
}

async function ensureProgramStageSubjectBaselineActivityTx(tx, stageSubjectTemplateId) {
  const normalizedStageSubjectTemplateId = normalizePositiveInt(stageSubjectTemplateId);
  if (!normalizedStageSubjectTemplateId) {
    return null;
  }
  const existingActivity = await tx.get(
    `
      SELECT id
      FROM academic_v2_program_stage_subject_activities
      WHERE stage_subject_template_id = ?
      LIMIT 1
    `,
    [normalizedStageSubjectTemplateId]
  );
  if (existingActivity) {
    return existingActivity;
  }
  return tx.get(
    `
      INSERT INTO academic_v2_program_stage_subject_activities
        (stage_subject_template_id, activity_type, sort_order, created_at, updated_at)
      VALUES (?, 'lecture', ?, NOW(), NOW())
      RETURNING *
    `,
    [normalizedStageSubjectTemplateId, ACTIVITY_ORDER.lecture]
  );
}

async function ensureGroupSubjectBaselineActivityTx(tx, groupSubjectId) {
  const normalizedGroupSubjectId = normalizePositiveInt(groupSubjectId);
  if (!normalizedGroupSubjectId) {
    return null;
  }
  const existingActivity = await tx.get(
    `
      SELECT id
      FROM academic_v2_group_subject_activities
      WHERE group_subject_id = ?
      LIMIT 1
    `,
    [normalizedGroupSubjectId]
  );
  if (existingActivity) {
    return existingActivity;
  }
  return tx.get(
    `
      INSERT INTO academic_v2_group_subject_activities
        (group_subject_id, activity_type, sort_order, created_at, updated_at)
      VALUES (?, 'lecture', ?, NOW(), NOW())
      RETURNING *
    `,
    [normalizedGroupSubjectId, ACTIVITY_ORDER.lecture]
  );
}

function stageNumberList() {
  return [1, 2, 3, 4];
}

function normalizeCleanupLimit(value, fallback = 25, max = 500) {
  const normalized = Number(value || fallback);
  if (Number.isInteger(normalized) && normalized > 0) {
    return Math.min(max, normalized);
  }
  return Math.min(max, Math.max(1, Number(fallback || 25) || 25));
}

function isAcademicV2SchemaCompatibilityError(err) {
  const code = String(err && err.code ? err.code : '').trim().toUpperCase();
  if (
    code === '42P01'
    || code === '42703'
    || code === '42P10'
    || code === '42883'
    || code === '42804'
    || code === '22P02'
  ) {
    return true;
  }
  if (code.startsWith('42') || code.startsWith('22')) {
    return true;
  }
  const message = String(err && err.message ? err.message : err || '').toLowerCase();
  if (!message) return false;
  return (
    message.includes('does not exist')
    || message.includes('no such table')
    || message.includes('no such column')
    || message.includes('undefined table')
    || message.includes('undefined column')
    || message.includes('operator does not exist')
    || message.includes('cannot cast type')
    || message.includes('invalid input syntax for type')
  );
}

async function getCountSafely(store, sql, params = []) {
  try {
    const row = await store.get(sql, params);
    return Number(row && row.count ? row.count : 0);
  } catch (err) {
    if (isAcademicV2SchemaCompatibilityError(err)) {
      return 0;
    }
    throw err;
  }
}

async function allRowsSafely(work, fallback = []) {
  try {
    const rows = await work();
    return Array.isArray(rows) ? rows : fallback;
  } catch (err) {
    if (isAcademicV2SchemaCompatibilityError(err)) {
      return Array.isArray(fallback) ? fallback : [];
    }
    throw err;
  }
}

function sortPrograms(a, b) {
  const trackDiff = Number(TRACK_ORDER[a.track_key] ?? 99) - Number(TRACK_ORDER[b.track_key] ?? 99);
  if (trackDiff !== 0) return trackDiff;
  const orderDiff = Number(a.sort_order || 0) - Number(b.sort_order || 0);
  if (orderDiff !== 0) return orderDiff;
  return String(a.name || '').localeCompare(String(b.name || ''), 'uk', { sensitivity: 'base' });
}

function sortScheduleEntries(a, b) {
  const termDiff = Number(a.term_number || 0) - Number(b.term_number || 0);
  if (termDiff !== 0) return termDiff;
  const dayDiff = Number(DAY_ORDER[String(a.day_of_week || '').toLowerCase()] || 99)
    - Number(DAY_ORDER[String(b.day_of_week || '').toLowerCase()] || 99);
  if (dayDiff !== 0) return dayDiff;
  const classDiff = Number(a.class_number || 0) - Number(b.class_number || 0);
  if (classDiff !== 0) return classDiff;
  const weekDiff = Number(a.week_number || 0) - Number(b.week_number || 0);
  if (weekDiff !== 0) return weekDiff;
  const activityDiff = Number(ACTIVITY_ORDER[normalizeActivityType(a.activity_type || a.lesson_type, 'lecture')] || 999)
    - Number(ACTIVITY_ORDER[normalizeActivityType(b.activity_type || b.lesson_type, 'lecture')] || 999);
  if (activityDiff !== 0) return activityDiff;
  return Number(a.group_number || 0) - Number(b.group_number || 0);
}

function buildFocusState(rawFocus = {}, data = {}) {
  const programs = Array.isArray(data.programs) ? data.programs : [];
  const cohorts = Array.isArray(data.cohorts) ? data.cohorts : [];
  const groups = Array.isArray(data.groups) ? data.groups : [];
  const terms = Array.isArray(data.terms) ? data.terms : [];

  let programId = normalizePositiveInt(rawFocus.programId);
  if (!programs.some((item) => Number(item.id) === Number(programId || 0))) {
    programId = programs[0] ? Number(programs[0].id || 0) : null;
  }

  const scopedCohorts = cohorts.filter((item) => Number(item.program_id || 0) === Number(programId || 0));
  let cohortId = normalizePositiveInt(rawFocus.cohortId);
  if (!scopedCohorts.some((item) => Number(item.id) === Number(cohortId || 0))) {
    cohortId = scopedCohorts[0] ? Number(scopedCohorts[0].id || 0) : null;
  }

  const scopedGroups = groups.filter((item) => Number(item.cohort_id || 0) === Number(cohortId || 0));
  let groupId = normalizePositiveInt(rawFocus.groupId);
  if (!scopedGroups.some((item) => Number(item.id) === Number(groupId || 0))) {
    groupId = null;
  }

  const scopedTerms = terms.filter((item) => Number(item.group_id || 0) === Number(groupId || 0));
  let termId = normalizePositiveInt(rawFocus.termId);
  if (!groupId) {
    termId = null;
  } else if (!scopedTerms.some((item) => Number(item.id) === Number(termId || 0))) {
    const activeTerm = scopedTerms.find((item) => item.is_active === true);
    termId = activeTerm ? Number(activeTerm.id || 0) : (scopedTerms[0] ? Number(scopedTerms[0].id || 0) : null);
  }

  return {
    programId,
    cohortId,
    groupId,
    termId,
  };
}

async function listPrograms(store) {
  const rows = await store.all(
    `
      SELECT
        p.*,
        COUNT(DISTINCT c.id)::int AS cohort_count,
        COUNT(DISTINCT g.id)::int AS group_count
      FROM academic_v2_programs p
      LEFT JOIN academic_v2_cohorts c ON c.program_id = p.id
      LEFT JOIN academic_v2_groups g ON g.cohort_id = c.id
      GROUP BY p.id
      ORDER BY
        CASE p.track_key
          WHEN 'bachelor' THEN 0
          WHEN 'master' THEN 1
          WHEN 'teacher' THEN 2
          ELSE 3
        END,
        COALESCE(p.sort_order, 100),
        p.name
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    cohort_count: Number(row.cohort_count || 0),
    group_count: Number(row.group_count || 0),
    sort_order: Number(row.sort_order || 0),
    legacy_program_id: normalizePositiveInt(row.legacy_program_id),
    is_active: row.is_active === true || Number(row.is_active) === 1,
    track_key: normalizeTrackKey(row.track_key, 'bachelor'),
  })).sort(sortPrograms);
}

async function listCohorts(store) {
  const rows = await store.all(
    `
      SELECT
        c.*,
        p.track_key,
        p.name AS program_name,
        p.code AS program_code,
        COUNT(DISTINCT g.id)::int AS group_count,
        COUNT(DISTINCT e.user_id)::int AS enrolled_users
      FROM academic_v2_cohorts c
      JOIN academic_v2_programs p ON p.id = c.program_id
      LEFT JOIN academic_v2_groups g ON g.cohort_id = c.id
      LEFT JOIN academic_v2_student_enrollments e ON e.group_id = g.id
      GROUP BY c.id, p.track_key, p.name, p.code
      ORDER BY
        CASE p.track_key
          WHEN 'bachelor' THEN 0
          WHEN 'master' THEN 1
          WHEN 'teacher' THEN 2
          ELSE 3
        END,
        c.admission_year DESC,
        c.label ASC,
        c.id ASC
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    program_id: Number(row.program_id || 0),
    admission_year: Number(row.admission_year || 0),
    current_stage_number: normalizeCourseStageNumber(row.current_stage_number, 1),
    group_count: Number(row.group_count || 0),
    enrolled_users: Number(row.enrolled_users || 0),
    legacy_admission_id: normalizePositiveInt(row.legacy_admission_id),
    is_active: row.is_active === true || Number(row.is_active) === 1,
    track_key: normalizeTrackKey(row.track_key, 'bachelor'),
  }));
}

async function listGroups(store) {
  const rows = await store.all(
    `
      SELECT
        g.*,
        c.admission_year,
        c.label AS cohort_label,
        p.id AS program_id,
        p.name AS program_name,
        p.track_key,
        COUNT(DISTINCT t.id)::int AS term_count,
        COUNT(DISTINCT gs.id)::int AS group_subject_count,
        COUNT(DISTINCT e.user_id)::int AS enrolled_users
      FROM academic_v2_groups g
      JOIN academic_v2_cohorts c ON c.id = g.cohort_id
      JOIN academic_v2_programs p ON p.id = c.program_id
      LEFT JOIN academic_v2_terms t ON t.group_id = g.id
      LEFT JOIN academic_v2_group_subjects gs ON gs.group_id = g.id
      LEFT JOIN academic_v2_student_enrollments e ON e.group_id = g.id
      GROUP BY g.id, c.admission_year, c.label, p.id, p.name, p.track_key
      ORDER BY
        CASE p.track_key
          WHEN 'bachelor' THEN 0
          WHEN 'master' THEN 1
          WHEN 'teacher' THEN 2
          ELSE 3
        END,
        c.admission_year DESC,
        g.stage_number ASC,
        g.campus_key ASC,
        g.label ASC
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    cohort_id: Number(row.cohort_id || 0),
    program_id: Number(row.program_id || 0),
    admission_year: Number(row.admission_year || 0),
    stage_number: normalizeCourseStageNumber(row.stage_number, 1),
    term_count: Number(row.term_count || 0),
    group_subject_count: Number(row.group_subject_count || 0),
    enrolled_users: Number(row.enrolled_users || 0),
    legacy_course_id: normalizePositiveInt(row.legacy_course_id),
    legacy_study_context_id: normalizePositiveInt(row.legacy_study_context_id),
    is_teacher_registration_default: row.is_teacher_registration_default === true || Number(row.is_teacher_registration_default) === 1,
    is_active: row.is_active === true || Number(row.is_active) === 1,
    track_key: normalizeTrackKey(row.track_key, 'bachelor'),
    campus_key: normalizeCampusKey(row.campus_key, 'kyiv'),
  }));
}

async function listRegistrationGroupAuditRows(store) {
  if (!store || typeof store.all !== 'function') {
    return [];
  }
  const rows = await allRowsSafely(() => store.all(
    `
      SELECT
        g.id AS group_id,
        g.stage_number,
        g.campus_key,
        g.label AS group_label,
        g.legacy_course_id,
        g.legacy_study_context_id,
        g.is_teacher_registration_default,
        c.id AS cohort_id,
        c.program_id,
        c.admission_year,
        c.label AS cohort_label,
        c.legacy_admission_id,
        p.track_key,
        p.name AS program_name,
        p.code AS program_code,
        p.legacy_program_id,
        EXISTS (
          SELECT 1
          FROM academic_v2_terms term
          WHERE term.group_id = g.id
            AND ${sqlFalsyExpr('term.is_archived', false)}
            AND ${sqlTruthyExpr('term.is_active', false)}
        ) AS has_active_term,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_group_subjects subject
          WHERE subject.group_id = g.id
            AND ${sqlTruthyExpr('subject.is_visible', true)}
        ) AS visible_subject_count,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_group_subjects subject
          WHERE subject.group_id = g.id
            AND ${sqlTruthyExpr('subject.is_visible', true)}
            AND subject.legacy_subject_id IS NOT NULL
        ) AS visible_mapped_subject_count
      FROM academic_v2_groups g
      JOIN academic_v2_cohorts c ON c.id = g.cohort_id
      JOIN academic_v2_programs p ON p.id = c.program_id
      WHERE ${sqlTruthyExpr('g.is_active', true)}
        AND ${sqlTruthyExpr('c.is_active', true)}
        AND ${sqlTruthyExpr('p.is_active', true)}
        AND g.stage_number = 1
      ORDER BY
        CASE p.track_key
          WHEN 'bachelor' THEN 0
          WHEN 'master' THEN 1
          WHEN 'teacher' THEN 2
          ELSE 3
        END,
        LOWER(COALESCE(p.name, '')) ASC,
        c.admission_year DESC,
        g.campus_key ASC,
        LOWER(COALESCE(g.label, '')) ASC,
        g.id ASC
    `
  ), []);
  return (rows || []).map((row) => ({
    group_id: normalizePositiveInt(row.group_id),
    program_id: normalizePositiveInt(row.program_id),
    cohort_id: normalizePositiveInt(row.cohort_id),
    track_key: normalizeTrackKey(row.track_key, 'bachelor'),
    campus_key: normalizeCampusKey(row.campus_key, 'kyiv'),
    stage_number: normalizeCourseStageNumber(row.stage_number, 1),
    group_label: cleanText(row.group_label, 160),
    program_name: cleanText(row.program_name, 160),
    program_code: cleanText(row.program_code, 80),
    cohort_label: cleanText(row.cohort_label, 160),
    admission_year: normalizePositiveInt(row.admission_year),
    legacy_course_id: normalizePositiveInt(row.legacy_course_id),
    legacy_study_context_id: normalizePositiveInt(row.legacy_study_context_id),
    legacy_program_id: normalizePositiveInt(row.legacy_program_id),
    legacy_admission_id: normalizePositiveInt(row.legacy_admission_id),
    is_teacher_registration_default: row.is_teacher_registration_default === true || Number(row.is_teacher_registration_default) === 1,
    has_active_term: normalizeBoolean(row.has_active_term, false),
    visible_subject_count: Math.max(0, Number(row.visible_subject_count || 0) || 0),
    visible_mapped_subject_count: Math.max(0, Number(row.visible_mapped_subject_count || 0) || 0),
  })).filter((row) => (
    row.group_id
    && row.program_id
    && row.cohort_id
  ));
}

function buildRegistrationGroupScopeKey(row = {}) {
  return [
    normalizePositiveInt(row.program_id) || 0,
    normalizePositiveInt(row.cohort_id) || 0,
    normalizeTrackKey(row.track_key, 'bachelor'),
    normalizeCampusKey(row.campus_key, 'kyiv'),
    normalizeCourseStageNumber(row.stage_number, 1),
  ].join('::');
}

function buildTeacherRegistrationGroupScopeKey(row = {}) {
  return [
    normalizePositiveInt(row.program_id) || 0,
    normalizeTrackKey(row.track_key, 'teacher'),
    normalizeCampusKey(row.campus_key, 'kyiv'),
    normalizeCourseStageNumber(row.stage_number, 1),
  ].join('::');
}

function collectRegistrationMissingCompatFields(row = {}) {
  const missingCompatFields = [];
  if (!normalizePositiveInt(row.legacy_course_id)) missingCompatFields.push('legacy_course_id');
  if (!normalizePositiveInt(row.legacy_study_context_id)) missingCompatFields.push('legacy_study_context_id');
  if (!normalizePositiveInt(row.legacy_program_id)) missingCompatFields.push('legacy_program_id');
  if (!normalizePositiveInt(row.legacy_admission_id)) missingCompatFields.push('legacy_admission_id');
  return missingCompatFields;
}

function buildRegistrationCatalogCandidateState(row = {}) {
  const visibleSubjectCount = Math.max(0, Number(row.visible_subject_count || 0) || 0);
  const visibleMappedSubjectCount = Math.max(0, Number(row.visible_mapped_subject_count || 0) || 0);
  const missingCompatFields = collectRegistrationMissingCompatFields(row);
  const blockingIssueCodes = [];
  const warningIssueCodes = [];
  if (visibleSubjectCount < 1) {
    blockingIssueCodes.push('missing_visible_subjects');
  } else if (visibleMappedSubjectCount < 1) {
    warningIssueCodes.push('missing_mapped_subjects');
  }
  if (missingCompatFields.length) {
    warningIssueCodes.push('missing_compat_bridge');
  }
  if (!normalizeBoolean(row.has_active_term, false)) {
    warningIssueCodes.push('missing_active_term');
  }
  const issueCodes = blockingIssueCodes.concat(warningIssueCodes);
  return {
    candidate: !blockingIssueCodes.length,
    issue_codes: issueCodes,
    blocking_issue_codes: blockingIssueCodes,
    warning_issue_codes: warningIssueCodes,
    missing_compat_fields: missingCompatFields,
  };
}

function buildRegistrationGroupReadinessState(row = {}) {
  const visibleSubjectCount = Math.max(0, Number(row.visible_subject_count || 0) || 0);
  const visibleMappedSubjectCount = Math.max(0, Number(row.visible_mapped_subject_count || 0) || 0);
  const missingCompatFields = collectRegistrationMissingCompatFields(row);
  const blockingIssueCodes = [];
  const warningIssueCodes = [];
  if (visibleSubjectCount < 1) {
    blockingIssueCodes.push('missing_visible_subjects');
  } else if (visibleMappedSubjectCount < 1) {
    blockingIssueCodes.push('missing_mapped_subjects');
  }
  if (missingCompatFields.length) {
    blockingIssueCodes.push('missing_compat_bridge');
  }
  if (!normalizeBoolean(row.has_active_term, false)) {
    warningIssueCodes.push('missing_active_term');
  }
  const issueCodes = blockingIssueCodes.concat(warningIssueCodes);
  return {
    ready: !blockingIssueCodes.length,
    issue_codes: issueCodes,
    blocking_issue_codes: blockingIssueCodes,
    warning_issue_codes: warningIssueCodes,
    missing_compat_fields: missingCompatFields,
  };
}

function resolveTeacherRegistrationBucket(rows = [], options = {}) {
  const bucketRows = Array.isArray(rows) ? rows : [];
  const eligibility = typeof options.eligibility === 'function'
    ? options.eligibility
    : (row) => buildRegistrationGroupReadinessState(row).ready;
  const eligibleRows = bucketRows.filter((row) => eligibility(row));
  const defaultRows = eligibleRows.filter((row) => row.is_teacher_registration_default === true);
  if (defaultRows.length === 1) {
    return {
      chosenRow: defaultRows[0],
      eligibleRows,
      readyRows: eligibleRows,
      defaultRows,
      issueCode: '',
    };
  }
  if (defaultRows.length > 1) {
    return {
      chosenRow: null,
      eligibleRows,
      readyRows: eligibleRows,
      defaultRows,
      issueCode: 'registration_teacher_multiple_defaults',
    };
  }
  if (eligibleRows.length === 1) {
    return {
      chosenRow: eligibleRows[0],
      eligibleRows,
      readyRows: eligibleRows,
      defaultRows,
      issueCode: '',
    };
  }
  if (eligibleRows.length > 1) {
    return {
      chosenRow: null,
      eligibleRows,
      readyRows: eligibleRows,
      defaultRows,
      issueCode: 'registration_teacher_default_required',
    };
  }
  return {
    chosenRow: null,
    eligibleRows,
    readyRows: eligibleRows,
    defaultRows,
    issueCode: '',
  };
}

async function listRegistrationCatalogGroups(store) {
  const rows = await listRegistrationGroupAuditRows(store);
  const catalogRows = (rows || []).filter((row) => buildRegistrationCatalogCandidateState(row).candidate);
  const duplicateCounts = new Map();
  const teacherBuckets = new Map();
  const teacherResolutions = new Map();
  catalogRows.forEach((row) => {
    if (normalizeTrackKey(row.track_key, 'bachelor') === 'teacher') {
      const teacherScopeKey = buildTeacherRegistrationGroupScopeKey(row);
      if (!teacherBuckets.has(teacherScopeKey)) {
        teacherBuckets.set(teacherScopeKey, []);
      }
      teacherBuckets.get(teacherScopeKey).push(row);
      return;
    }
    const scopeKey = buildRegistrationGroupScopeKey(row);
    duplicateCounts.set(scopeKey, Number(duplicateCounts.get(scopeKey) || 0) + 1);
  });
  teacherBuckets.forEach((bucket) => {
    const teacherScopeKey = buildTeacherRegistrationGroupScopeKey(bucket[0] || {});
    teacherResolutions.set(
      teacherScopeKey,
      resolveTeacherRegistrationBucket(bucket, {
        eligibility: (row) => buildRegistrationCatalogCandidateState(row).candidate,
      })
    );
  });
  return catalogRows.map((row) => {
    const catalogState = buildRegistrationCatalogCandidateState(row);
    const readinessState = buildRegistrationGroupReadinessState(row);
    let selectionBlockedIssueCode = '';
    if (normalizeTrackKey(row.track_key, 'bachelor') === 'teacher') {
      const resolution = teacherResolutions.get(buildTeacherRegistrationGroupScopeKey(row));
      if (resolution && resolution.issueCode) {
        selectionBlockedIssueCode = resolution.issueCode;
      } else if (
        resolution
        && resolution.chosenRow
        && Number(resolution.chosenRow.group_id || 0) !== Number(row.group_id || 0)
      ) {
        selectionBlockedIssueCode = 'registration_teacher_not_default';
      }
    } else if ((duplicateCounts.get(buildRegistrationGroupScopeKey(row)) || 0) !== 1) {
      selectionBlockedIssueCode = 'duplicate_stage_campus';
    }
    return {
      ...row,
      catalog_candidate: catalogState.candidate,
      catalog_issue_codes: catalogState.issue_codes,
      catalog_blocking_issue_codes: catalogState.blocking_issue_codes,
      catalog_warning_issue_codes: catalogState.warning_issue_codes,
      final_ready: readinessState.ready,
      final_ready_issue_codes: readinessState.issue_codes,
      final_ready_blocking_issue_codes: readinessState.blocking_issue_codes,
      final_ready_warning_issue_codes: readinessState.warning_issue_codes,
      missing_compat_fields: readinessState.missing_compat_fields,
      selection_blocked: Boolean(selectionBlockedIssueCode),
      selection_blocked_issue_code: selectionBlockedIssueCode,
    };
  });
}

async function listRegistrationReadyGroups(store) {
  const catalogRows = await listRegistrationCatalogGroups(store);
  return (catalogRows || []).filter((row) => (
    !row.selection_blocked
    && row.final_ready
  ));
}

async function listRegistrationGroupAuditIssues(store) {
  const rows = await listRegistrationGroupAuditRows(store);
  const catalogRows = (rows || []).filter((row) => buildRegistrationCatalogCandidateState(row).candidate);
  const buckets = new Map();
  const teacherBuckets = new Map();
  catalogRows.forEach((row) => {
    if (normalizeTrackKey(row.track_key, 'bachelor') === 'teacher') {
      const teacherScopeKey = buildTeacherRegistrationGroupScopeKey(row);
      if (!teacherBuckets.has(teacherScopeKey)) {
        teacherBuckets.set(teacherScopeKey, []);
      }
      teacherBuckets.get(teacherScopeKey).push(row);
    }
    const scopeKey = buildRegistrationGroupScopeKey(row);
    if (!buckets.has(scopeKey)) {
      buckets.set(scopeKey, []);
    }
    buckets.get(scopeKey).push(row);
  });

  const issues = [];
  buckets.forEach((bucket, scopeKey) => {
    const sample = bucket[0] || {};
    if ((bucket || []).length !== 1) {
      issues.push({
        issue_code: 'registration_group_duplicate_stage_campus',
        severity: 'high',
        source_group_id: normalizePositiveInt(sample.group_id),
        source_scope_key: scopeKey,
        program_id: normalizePositiveInt(sample.program_id),
        cohort_id: normalizePositiveInt(sample.cohort_id),
        track_key: normalizeTrackKey(sample.track_key, 'bachelor'),
        campus_key: normalizeCampusKey(sample.campus_key, 'kyiv'),
        stage_number: normalizeCourseStageNumber(sample.stage_number, 1),
        duplicate_group_ids: bucket.map((item) => normalizePositiveInt(item.group_id)).filter(Boolean),
        title: 'Registration has duplicate stage-1 academic groups for one campus',
        summary: 'Stage-1 registration must resolve exactly one active academic_v2 group per track, program, cohort, and campus.',
      });
    }
  });

  teacherBuckets.forEach((bucket, scopeKey) => {
    const resolution = resolveTeacherRegistrationBucket(bucket, {
      eligibility: (row) => buildRegistrationCatalogCandidateState(row).candidate,
    });
    if (!resolution.issueCode) {
      return;
    }
    const sample = bucket[0] || {};
    const duplicateGroupIds = resolution.issueCode === 'registration_teacher_multiple_defaults'
      ? resolution.defaultRows.map((item) => normalizePositiveInt(item.group_id)).filter(Boolean)
      : resolution.readyRows.map((item) => normalizePositiveInt(item.group_id)).filter(Boolean);
    issues.push({
      issue_code: resolution.issueCode,
      severity: 'high',
      source_group_id: normalizePositiveInt(sample.group_id),
      source_scope_key: scopeKey,
      program_id: normalizePositiveInt(sample.program_id),
      cohort_id: normalizePositiveInt(sample.cohort_id),
      track_key: 'teacher',
      campus_key: normalizeCampusKey(sample.campus_key, 'kyiv'),
      stage_number: normalizeCourseStageNumber(sample.stage_number, 1),
      duplicate_group_ids: duplicateGroupIds,
      title: resolution.issueCode === 'registration_teacher_multiple_defaults'
        ? 'Teacher registration has multiple default groups for one campus'
        : 'Teacher registration needs one default group for this campus',
      summary: resolution.issueCode === 'registration_teacher_multiple_defaults'
        ? 'Only one active teacher registration default group per program and campus can be used for registration.'
        : 'Multiple active teacher groups share one program and campus. Mark exactly one of them as the default registration group.',
    });
  });

  (rows || []).forEach((row) => {
    const scopeKey = buildRegistrationGroupScopeKey(row);
    const catalogState = buildRegistrationCatalogCandidateState(row);
    const readiness = buildRegistrationGroupReadinessState(row);
    if (!catalogState.issue_codes.length && !readiness.issue_codes.length) {
      return;
    }
    let issueCode = 'registration_group_not_ready';
    let severity = 'medium';
    let title = 'Registration academic group is not ready';
    let summary = 'The stage-1 academic_v2 group is excluded from registration because its configuration is incomplete.';
    if (catalogState.blocking_issue_codes.includes('missing_visible_subjects')) {
      issueCode = 'registration_group_missing_visible_subjects';
      title = 'Registration academic group has no visible subjects';
      summary = 'Registration stage-1 academic_v2 groups need at least one visible subject before the catalog can expose this pathway.';
    } else if (readiness.blocking_issue_codes.includes('missing_compat_bridge')) {
      issueCode = 'registration_group_missing_compat_bridge';
      severity = 'medium';
      title = 'Registration academic group is missing compatibility bridge ids';
      summary = 'Registration can still surface this pathway, but submit-time repair must project the required legacy bridge ids before placement can be saved.';
    } else if (readiness.blocking_issue_codes.includes('missing_mapped_subjects')) {
      issueCode = 'registration_group_missing_mapped_subjects';
      title = 'Registration academic group has no mapped visible subjects yet';
      summary = 'The catalog can surface this stage-1 group, but submit-time repair still needs to project at least one visible subject into legacy compatibility before subject selection can open.';
    } else if (readiness.warning_issue_codes.includes('missing_active_term')) {
      issueCode = 'registration_group_missing_active_term';
      severity = 'low';
      title = 'Registration academic group has no active term yet';
      summary = 'Registration stays available, but schedule views remain empty until one academic_v2 term becomes active.';
    }
    issues.push({
      issue_code: issueCode,
      severity,
      source_group_id: normalizePositiveInt(row.group_id),
      source_scope_key: scopeKey,
      program_id: normalizePositiveInt(row.program_id),
      cohort_id: normalizePositiveInt(row.cohort_id),
      track_key: normalizeTrackKey(row.track_key, 'bachelor'),
      campus_key: normalizeCampusKey(row.campus_key, 'kyiv'),
      stage_number: normalizeCourseStageNumber(row.stage_number, 1),
      group_id: normalizePositiveInt(row.group_id),
      visible_subject_count: Math.max(0, Number(row.visible_subject_count || 0) || 0),
      missing_compat_fields: readiness.missing_compat_fields,
      visible_mapped_subject_count: Math.max(0, Number(row.visible_mapped_subject_count || 0) || 0),
      has_active_term: normalizeBoolean(row.has_active_term, false),
      title,
      summary,
    });
  });

  return issues;
}

async function listTerms(store) {
  const rows = await store.all(
    `
      SELECT
        t.*,
        g.cohort_id
      FROM academic_v2_terms t
      JOIN academic_v2_groups g ON g.id = t.group_id
      ORDER BY g.cohort_id DESC, t.group_id ASC, t.term_number ASC, t.id ASC
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    group_id: Number(row.group_id || 0),
    cohort_id: Number(row.cohort_id || 0),
    term_number: Number(row.term_number || 0) || 1,
    weeks_count: normalizeWeeksCount(row.weeks_count, 16),
    legacy_semester_id: normalizePositiveInt(row.legacy_semester_id),
    is_active: row.is_active === true || Number(row.is_active) === 1,
    is_archived: row.is_archived === true || Number(row.is_archived) === 1,
  }));
}

async function listSubjectTemplates(store) {
  const rows = await store.all(
    `
      SELECT
        st.*,
        COUNT(DISTINCT gs.id)::int AS group_subject_count
      FROM academic_v2_subject_templates st
      LEFT JOIN academic_v2_group_subjects gs ON gs.subject_template_id = st.id
      GROUP BY st.id
      ORDER BY LOWER(st.name) ASC, st.id ASC
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    legacy_catalog_id: normalizePositiveInt(row.legacy_catalog_id),
    group_subject_count: Number(row.group_subject_count || 0),
    is_active: row.is_active === true || Number(row.is_active) === 1,
  }));
}

async function listProgramStageTermTemplates(store) {
  const rows = await store.all(
    `
      SELECT
        term_template.*,
        stage_template.program_id,
        stage_template.stage_number
      FROM academic_v2_program_stage_term_templates term_template
      JOIN academic_v2_program_stage_templates stage_template ON stage_template.id = term_template.stage_template_id
      ORDER BY
        stage_template.program_id ASC,
        stage_template.stage_number ASC,
        COALESCE(term_template.sort_order, 0) ASC,
        term_template.term_number ASC,
        term_template.id ASC
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    stage_template_id: Number(row.stage_template_id || 0),
    program_id: Number(row.program_id || 0),
    stage_number: normalizeCourseStageNumber(row.stage_number, 1),
    term_number: Number(row.term_number || 0) || 1,
    weeks_count: normalizeWeeksCount(row.weeks_count, 16),
    sort_order: normalizeSortOrder(row.sort_order, 0),
    is_active_default: row.is_active_default === true || Number(row.is_active_default) === 1,
  }));
}

async function listProgramStageSubjectTemplates(store) {
  const rows = await store.all(
    `
      SELECT
        stage_subject.*,
        stage_template.program_id,
        stage_template.stage_number,
        subject_template.name AS subject_template_name,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT stage_term.id), NULL),
          ARRAY[]::int[]
        ) AS stage_term_template_ids,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT stage_term.title), NULL),
          ARRAY[]::text[]
        ) AS stage_term_titles,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT teacher_link.user_id), NULL),
          ARRAY[]::int[]
        ) AS teacher_ids,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT teacher.full_name), NULL),
          ARRAY[]::text[]
        ) AS teacher_names,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT activity.activity_type), NULL),
          ARRAY[]::text[]
        ) AS activity_types
      FROM academic_v2_program_stage_subject_templates stage_subject
      JOIN academic_v2_program_stage_templates stage_template ON stage_template.id = stage_subject.stage_template_id
      JOIN academic_v2_subject_templates subject_template ON subject_template.id = stage_subject.subject_template_id
      LEFT JOIN academic_v2_program_stage_subject_terms stage_subject_term
        ON stage_subject_term.stage_subject_template_id = stage_subject.id
      LEFT JOIN academic_v2_program_stage_term_templates stage_term
        ON stage_term.id = stage_subject_term.stage_term_template_id
      LEFT JOIN academic_v2_program_stage_subject_teachers teacher_link
        ON teacher_link.stage_subject_template_id = stage_subject.id
      LEFT JOIN users teacher ON teacher.id = teacher_link.user_id
      LEFT JOIN academic_v2_program_stage_subject_activities activity
        ON activity.stage_subject_template_id = stage_subject.id
      GROUP BY stage_subject.id, stage_template.program_id, stage_template.stage_number, subject_template.name
      ORDER BY
        stage_template.program_id ASC,
        stage_template.stage_number ASC,
        stage_subject.sort_order ASC,
        COALESCE(NULLIF(stage_subject.title, ''), subject_template.name) ASC,
        stage_subject.id ASC
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    stage_template_id: Number(row.stage_template_id || 0),
    subject_template_id: Number(row.subject_template_id || 0),
    program_id: Number(row.program_id || 0),
    stage_number: normalizeCourseStageNumber(row.stage_number, 1),
    group_count: Math.max(1, Number(row.group_count || 0) || 1),
    default_group: Math.max(1, Number(row.default_group || 0) || 1),
    sort_order: normalizeSortOrder(row.sort_order, 0),
    is_visible: row.is_visible === true || Number(row.is_visible) === 1,
    is_required: row.is_required === true || Number(row.is_required) === 1,
    is_general: row.is_general === true || Number(row.is_general) === 1,
    show_in_teamwork: row.show_in_teamwork === true || Number(row.show_in_teamwork) === 1,
    stage_term_template_ids: normalizeIdArray(row.stage_term_template_ids || []),
    stage_term_titles: Array.isArray(row.stage_term_titles) ? row.stage_term_titles.filter(Boolean) : [],
    teacher_ids: normalizeIdArray(row.teacher_ids || []),
    teacher_names: Array.isArray(row.teacher_names) ? row.teacher_names.filter(Boolean) : [],
    activity_types: Array.from(new Set(
      (Array.isArray(row.activity_types) ? row.activity_types : [])
        .map((item) => normalizeActivityType(item, 'lecture'))
        .filter(Boolean)
    )).sort((a, b) => Number(ACTIVITY_ORDER[a] || 999) - Number(ACTIVITY_ORDER[b] || 999)),
  }));
}

async function listProgramStageSubjectActivities(store) {
  const rows = await store.all(
    `
      SELECT
        activity.*,
        stage_subject.stage_template_id,
        stage_subject.subject_template_id,
        stage_subject.title AS stage_subject_title,
        stage_template.program_id,
        stage_template.stage_number,
        subject_template.name AS subject_template_name
      FROM academic_v2_program_stage_subject_activities activity
      JOIN academic_v2_program_stage_subject_templates stage_subject ON stage_subject.id = activity.stage_subject_template_id
      JOIN academic_v2_program_stage_templates stage_template ON stage_template.id = stage_subject.stage_template_id
      JOIN academic_v2_subject_templates subject_template ON subject_template.id = stage_subject.subject_template_id
      ORDER BY
        stage_template.program_id ASC,
        stage_template.stage_number ASC,
        stage_subject.sort_order ASC,
        activity.sort_order ASC,
        activity.id ASC
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    stage_subject_template_id: Number(row.stage_subject_template_id || 0),
    stage_template_id: Number(row.stage_template_id || 0),
    subject_template_id: Number(row.subject_template_id || 0),
    program_id: Number(row.program_id || 0),
    stage_number: normalizeCourseStageNumber(row.stage_number, 1),
    sort_order: normalizeSortOrder(row.sort_order, ACTIVITY_ORDER[normalizeActivityType(row.activity_type, 'lecture')] || 0),
    activity_type: normalizeActivityType(row.activity_type, 'lecture'),
    activity_label: activityTypeLabel(row.activity_type),
    subject_title: cleanText(row.stage_subject_title || row.subject_template_name, 160),
  }));
}

async function listGroupSubjects(store) {
  const rows = await store.all(
    `
      SELECT
        gs.*,
        st.name AS template_name,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT gst.term_id), NULL),
          ARRAY[]::int[]
        ) AS term_ids,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT ta.user_id), NULL),
          ARRAY[]::int[]
        ) AS teacher_ids,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT term.title), NULL),
          ARRAY[]::text[]
        ) AS term_titles,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT teacher.full_name), NULL),
          ARRAY[]::text[]
        ) AS teacher_names,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT activity.activity_type), NULL),
          ARRAY[]::text[]
        ) AS activity_types
      FROM academic_v2_group_subjects gs
      JOIN academic_v2_subject_templates st ON st.id = gs.subject_template_id
      LEFT JOIN academic_v2_group_subject_terms gst ON gst.group_subject_id = gs.id
      LEFT JOIN academic_v2_terms term ON term.id = gst.term_id
      LEFT JOIN academic_v2_teacher_assignments ta ON ta.group_subject_id = gs.id
      LEFT JOIN users teacher ON teacher.id = ta.user_id
      LEFT JOIN academic_v2_group_subject_activities activity ON activity.group_subject_id = gs.id
      GROUP BY gs.id, st.name
      ORDER BY gs.group_id ASC, gs.sort_order ASC, gs.title ASC, gs.id ASC
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    group_id: Number(row.group_id || 0),
    subject_template_id: Number(row.subject_template_id || 0),
    group_count: Math.max(1, Number(row.group_count || 0) || 1),
    default_group: Math.max(1, Number(row.default_group || 0) || 1),
    sort_order: normalizeSortOrder(row.sort_order, 0),
    legacy_subject_id: normalizePositiveInt(row.legacy_subject_id),
    is_visible: row.is_visible === true || Number(row.is_visible) === 1,
    is_required: row.is_required === true || Number(row.is_required) === 1,
    is_general: row.is_general === true || Number(row.is_general) === 1,
    show_in_teamwork: row.show_in_teamwork === true || Number(row.show_in_teamwork) === 1,
    term_ids: normalizeIdArray(row.term_ids || []),
    teacher_ids: normalizeIdArray(row.teacher_ids || []),
    term_titles: Array.isArray(row.term_titles) ? row.term_titles.filter(Boolean) : [],
    teacher_names: Array.isArray(row.teacher_names) ? row.teacher_names.filter(Boolean) : [],
    activity_types: Array.from(new Set(
      (Array.isArray(row.activity_types) ? row.activity_types : [])
        .map((item) => normalizeActivityType(item, 'lecture'))
        .filter(Boolean)
    )).sort((a, b) => Number(ACTIVITY_ORDER[a] || 999) - Number(ACTIVITY_ORDER[b] || 999)),
  }));
}

async function listGroupSubjectActivities(store) {
  const rows = await store.all(
    `
      SELECT
        activity.*,
        gs.group_id,
        gs.subject_template_id,
        gs.title AS subject_title,
        st.name AS template_name,
        gs.group_count,
        gs.default_group
      FROM academic_v2_group_subject_activities activity
      JOIN academic_v2_group_subjects gs ON gs.id = activity.group_subject_id
      JOIN academic_v2_subject_templates st ON st.id = gs.subject_template_id
      ORDER BY
        gs.group_id ASC,
        gs.sort_order ASC,
        activity.sort_order ASC,
        activity.id ASC
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    group_subject_id: Number(row.group_subject_id || 0),
    group_id: Number(row.group_id || 0),
    subject_template_id: Number(row.subject_template_id || 0),
    group_count: Math.max(1, Number(row.group_count || 0) || 1),
    default_group: Math.max(1, Number(row.default_group || 0) || 1),
    sort_order: normalizeSortOrder(row.sort_order, ACTIVITY_ORDER[normalizeActivityType(row.activity_type, 'lecture')] || 0),
    activity_type: normalizeActivityType(row.activity_type, 'lecture'),
    activity_label: activityTypeLabel(row.activity_type),
    subject_title: cleanText(row.subject_title || row.template_name, 160),
  }));
}

async function listScheduleEntries(store) {
  const rows = await store.all(
    `
      SELECT
        se.*,
        activity.activity_type,
        activity.sort_order AS activity_sort_order,
        gs.group_id,
        gs.title AS subject_title,
        st.name AS template_name,
        gs.group_count,
        t.term_number,
        t.title AS term_title
      FROM academic_v2_schedule_entries se
      JOIN academic_v2_group_subject_activities activity ON activity.id = se.group_subject_activity_id
      JOIN academic_v2_group_subjects gs ON gs.id = activity.group_subject_id
      JOIN academic_v2_subject_templates st ON st.id = gs.subject_template_id
      JOIN academic_v2_terms t ON t.id = se.term_id
      ORDER BY gs.group_id ASC, t.term_number ASC, se.day_of_week ASC, se.class_number ASC, se.week_number ASC, activity.sort_order ASC, se.id ASC
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    group_id: Number(row.group_id || 0),
    group_subject_id: Number(row.group_subject_id || 0),
    group_subject_activity_id: Number(row.group_subject_activity_id || 0),
    term_id: Number(row.term_id || 0),
    group_number: deriveScheduleGroupNumber(
      row.activity_type || row.lesson_type,
      row.target_group_numbers || [],
      row.group_number
    ),
    target_group_numbers: deriveScheduleTargetGroups(
      row.activity_type || row.lesson_type,
      row.target_group_numbers || [],
      row.group_number,
      row.group_count
    ),
    class_number: Math.max(1, Number(row.class_number || 0) || 1),
    week_number: Math.max(1, Number(row.week_number || 0) || 1),
    term_number: Number(row.term_number || 0) || 1,
    legacy_schedule_entry_id: normalizePositiveInt(row.legacy_schedule_entry_id),
    day_of_week: normalizeDayOfWeek(row.day_of_week, 'Monday'),
    lesson_type: normalizeActivityType(row.activity_type || row.lesson_type, 'lecture'),
    activity_type: normalizeActivityType(row.activity_type || row.lesson_type, 'lecture'),
    activity_label: activityTypeLabel(row.activity_type || row.lesson_type),
    target_group_label: buildScheduleTargetGroupLabel(row.activity_type || row.lesson_type, row.target_group_numbers || []),
    group_count: Math.max(1, Number(row.group_count || 0) || 1),
  })).sort(sortScheduleEntries);
}

async function listTeacherOptions(store) {
  const rows = await store.all(
    `
      SELECT id, full_name
      FROM users
      WHERE role = 'teacher'
        AND ${sqlTruthyExpr('is_active', true)}
      ORDER BY full_name ASC
    `
  );
  return (rows || []).map((row) => ({
    id: Number(row.id || 0),
    full_name: cleanText(row.full_name, 160),
  }));
}

async function listAssignableUsers(store) {
  const rows = await store.all(
    `
      SELECT
        u.id,
        u.full_name,
        u.role,
        u.schedule_group,
        u.course_id,
        u.group_id,
        legacy_course.name AS legacy_course_name,
        g.label AS group_label
      FROM users u
      LEFT JOIN courses legacy_course ON legacy_course.id = u.course_id
      LEFT JOIN academic_v2_groups g ON g.id = u.group_id
      WHERE ${sqlTruthyExpr('u.is_active', true)}
        AND u.role NOT IN ('admin', 'teacher')
      ORDER BY
        CASE u.role
          WHEN 'starosta' THEN 0
          WHEN 'student' THEN 1
          WHEN 'deanery' THEN 2
          ELSE 3
        END,
        u.full_name ASC
    `
  );
  return (rows || []).map((row) => ({
    id: Number(row.id || 0),
    full_name: cleanText(row.full_name, 160),
    role: cleanText(row.role, 40),
    schedule_group: cleanText(row.schedule_group, 20),
    course_id: normalizePositiveInt(row.course_id),
    group_id: normalizePositiveInt(row.group_id),
    legacy_course_name: cleanText(row.legacy_course_name, 160),
    group_label: cleanText(row.group_label, 160),
  }));
}

async function buildDashboardSummary(store) {
  const row = await store.get(
    `
      SELECT
        (SELECT COUNT(*)::int FROM academic_v2_programs) AS programs_total,
        (SELECT COUNT(*)::int FROM academic_v2_cohorts) AS cohorts_total,
        (SELECT COUNT(*)::int FROM academic_v2_groups) AS groups_total,
        (SELECT COUNT(*)::int FROM academic_v2_terms) AS terms_total,
        (SELECT COUNT(*)::int FROM academic_v2_subject_templates) AS templates_total,
        (SELECT COUNT(*)::int FROM academic_v2_group_subjects) AS group_subjects_total,
        (SELECT COUNT(*)::int FROM academic_v2_schedule_entries) AS schedule_entries_total,
        (SELECT COUNT(*)::int FROM academic_v2_student_enrollments) AS enrollments_total
    `
  );
  return {
    programs_total: Number(row?.programs_total || 0),
    cohorts_total: Number(row?.cohorts_total || 0),
    groups_total: Number(row?.groups_total || 0),
    terms_total: Number(row?.terms_total || 0),
    templates_total: Number(row?.templates_total || 0),
    group_subjects_total: Number(row?.group_subjects_total || 0),
    schedule_entries_total: Number(row?.schedule_entries_total || 0),
    enrollments_total: Number(row?.enrollments_total || 0),
  };
}

function buildGroupProjectionIssues(row = {}) {
  const issues = [];
  if (!normalizePositiveInt(row.legacy_course_id)) {
    issues.push('legacy course');
  }
  if (Number(row.term_count || 0) < 1) {
    issues.push('terms');
  }
  if (Number(row.active_term_count || 0) < 1) {
    issues.push('active term');
  }
  if (Number(row.term_count || 0) > Number(row.projected_term_count || 0)) {
    issues.push('legacy semesters');
  }
  if (Number(row.subject_count || 0) > Number(row.projected_subject_count || 0)) {
    issues.push('legacy subjects');
  }
  if (Number(row.subject_count || 0) > Number(row.teacher_ready_subject_count || 0)) {
    issues.push('teacher coverage');
  }
  if (Number(row.schedule_count || 0) > Number(row.projected_schedule_count || 0)) {
    issues.push('schedule projection');
  }
  if (Number(row.enrollment_count || 0) > Number(row.synced_user_count || 0)) {
    issues.push('user sync');
  }
  return issues;
}

function buildProjectionHealthSummary(items = []) {
  const normalizedItems = Array.isArray(items) ? items : [];
  return normalizedItems.reduce((summary, item) => {
    const issues = Array.isArray(item.issues) ? item.issues : [];
    if (issues.length) {
      summary.groups_with_issues += 1;
    } else {
      summary.groups_healthy += 1;
    }
    if (!item.legacy_course_id) summary.groups_missing_legacy_course += 1;
    if (Number(item.term_count || 0) < 1) summary.groups_without_terms += 1;
    if (Number(item.active_term_count || 0) < 1) summary.groups_without_active_term += 1;
    if (Number(item.subject_count || 0) > Number(item.projected_subject_count || 0)) summary.groups_with_subject_projection_gaps += 1;
    if (Number(item.schedule_count || 0) > Number(item.projected_schedule_count || 0)) summary.groups_with_schedule_projection_gaps += 1;
    if (Number(item.enrollment_count || 0) > Number(item.synced_user_count || 0)) summary.groups_with_user_sync_gaps += 1;
    summary.subjects_without_teachers += Math.max(
      0,
      Number(item.subject_count || 0) - Number(item.teacher_ready_subject_count || 0)
    );
    return summary;
  }, {
    groups_total: normalizedItems.length,
    groups_healthy: 0,
    groups_with_issues: 0,
    groups_missing_legacy_course: 0,
    groups_without_terms: 0,
    groups_without_active_term: 0,
    groups_with_subject_projection_gaps: 0,
    groups_with_schedule_projection_gaps: 0,
    groups_with_user_sync_gaps: 0,
    subjects_without_teachers: 0,
  });
}

async function listProjectionHealth(store) {
  const rows = await store.all(
    `
      SELECT
        g.id AS group_id,
        g.cohort_id,
        g.label AS group_label,
        g.stage_number,
        g.campus_key,
        g.legacy_course_id,
        g.legacy_study_context_id,
        c.label AS cohort_label,
        c.admission_year,
        p.id AS program_id,
        p.name AS program_name,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_terms term
          WHERE term.group_id = g.id
        ) AS term_count,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_terms term
          WHERE term.group_id = g.id
            AND term.legacy_semester_id IS NOT NULL
        ) AS projected_term_count,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_terms term
          WHERE term.group_id = g.id
            AND ${sqlTruthyExpr('term.is_active', false)}
        ) AS active_term_count,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_group_subjects subject
          WHERE subject.group_id = g.id
        ) AS subject_count,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_group_subjects subject
          WHERE subject.group_id = g.id
            AND subject.legacy_subject_id IS NOT NULL
        ) AS projected_subject_count,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_group_subjects subject
          WHERE subject.group_id = g.id
            AND EXISTS (
              SELECT 1
              FROM academic_v2_teacher_assignments assignment
              WHERE assignment.group_subject_id = subject.id
            )
        ) AS teacher_ready_subject_count,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_schedule_entries entry
          JOIN academic_v2_group_subject_activities activity ON activity.id = entry.group_subject_activity_id
          JOIN academic_v2_group_subjects subject ON subject.id = activity.group_subject_id
          WHERE subject.group_id = g.id
        ) AS schedule_count,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_schedule_entries entry
          JOIN academic_v2_group_subject_activities activity ON activity.id = entry.group_subject_activity_id
          JOIN academic_v2_group_subjects subject ON subject.id = activity.group_subject_id
          LEFT JOIN (
            SELECT schedule_entry_id, COUNT(*)::int AS link_count
            FROM academic_v2_schedule_entry_legacy_links
            GROUP BY schedule_entry_id
          ) projected ON projected.schedule_entry_id = entry.id
          WHERE subject.group_id = g.id
            AND COALESCE(projected.link_count, 0) = CASE
              WHEN COALESCE(activity.activity_type, entry.lesson_type) = 'lecture' THEN 1
              ELSE GREATEST(COALESCE(array_length(entry.target_group_numbers, 1), 0), 1)
            END
        ) AS projected_schedule_count,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_student_enrollments enrollment
          WHERE enrollment.group_id = g.id
        ) AS enrollment_count,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_student_enrollments enrollment
          JOIN users u ON u.id = enrollment.user_id
          WHERE enrollment.group_id = g.id
            AND ${sqlTruthyExpr('u.is_active', true)}
            AND COALESCE(u.group_id, 0) = g.id
            AND (
              g.legacy_course_id IS NULL
              OR COALESCE(u.course_id, 0) = g.legacy_course_id
            )
        ) AS synced_user_count
      FROM academic_v2_groups g
      JOIN academic_v2_cohorts c ON c.id = g.cohort_id
      JOIN academic_v2_programs p ON p.id = c.program_id
      ORDER BY
        CASE p.track_key
          WHEN 'bachelor' THEN 0
          WHEN 'master' THEN 1
          WHEN 'teacher' THEN 2
          ELSE 3
        END,
        c.admission_year DESC,
        g.stage_number ASC,
        g.campus_key ASC,
        g.label ASC
    `
  );
  const items = (rows || []).map((row) => {
    const normalizedRow = {
      ...row,
      group_id: Number(row.group_id || 0),
      cohort_id: Number(row.cohort_id || 0),
      program_id: Number(row.program_id || 0),
      admission_year: Number(row.admission_year || 0),
      stage_number: normalizeStageNumber(row.stage_number, 1),
      campus_key: normalizeCampusKey(row.campus_key, 'kyiv'),
      legacy_course_id: normalizePositiveInt(row.legacy_course_id),
      legacy_study_context_id: normalizePositiveInt(row.legacy_study_context_id),
      term_count: Number(row.term_count || 0),
      projected_term_count: Number(row.projected_term_count || 0),
      active_term_count: Number(row.active_term_count || 0),
      subject_count: Number(row.subject_count || 0),
      projected_subject_count: Number(row.projected_subject_count || 0),
      teacher_ready_subject_count: Number(row.teacher_ready_subject_count || 0),
      schedule_count: Number(row.schedule_count || 0),
      projected_schedule_count: Number(row.projected_schedule_count || 0),
      enrollment_count: Number(row.enrollment_count || 0),
      synced_user_count: Number(row.synced_user_count || 0),
    };
    const issues = buildGroupProjectionIssues(normalizedRow);
    return {
      ...normalizedRow,
      issues,
      is_healthy: issues.length === 0,
    };
  });
  return {
    items,
    summary: buildProjectionHealthSummary(items),
  };
}

async function listStaleStudyContextRows(store, limit = null) {
  const normalizedLimit = Number.isInteger(Number(limit)) && Number(limit) > 0
    ? Math.max(1, Number(limit))
    : null;
  const limitClause = normalizedLimit ? `LIMIT ${normalizedLimit}` : '';
  return allRowsSafely(() => store.all(
    `
      SELECT
        context.id,
        context.stage_number,
        context.campus_key,
        context.label,
        context.is_active,
        primary_binding.course_id,
        legacy_course.name AS course_name
      FROM study_contexts context
      LEFT JOIN LATERAL (
        SELECT sccb.course_id
        FROM study_context_course_bindings sccb
        WHERE sccb.study_context_id = context.id
        ORDER BY sccb.is_primary DESC, sccb.course_id ASC
        LIMIT 1
      ) primary_binding ON TRUE
      LEFT JOIN courses legacy_course ON legacy_course.id = primary_binding.course_id
      WHERE ${sqlTruthyExpr('context.is_active', true)}
        AND NOT EXISTS (
          SELECT 1
          FROM academic_v2_groups g
          WHERE g.legacy_study_context_id = context.id
        )
      ORDER BY primary_binding.course_id ASC NULLS LAST, context.stage_number ASC, context.id ASC
      ${limitClause}
    `
  ));
}

async function listStaleProgramPresetRows(store, limit = null) {
  const normalizedLimit = Number.isInteger(Number(limit)) && Number(limit) > 0
    ? Math.max(1, Number(limit))
    : null;
  const limitClause = normalizedLimit ? `LIMIT ${normalizedLimit}` : '';
  return allRowsSafely(() => store.all(
    `
      SELECT
        preset.id,
        preset.program_id,
        preset.name,
        preset.is_default,
        preset.is_active,
        preset.source_cohort_id,
        legacy_program.name AS legacy_program_name,
        source_cohort.label AS source_cohort_label,
        source_cohort.legacy_admission_id AS source_admission_id
      FROM program_presets preset
      LEFT JOIN study_programs legacy_program ON legacy_program.id = preset.program_id
      LEFT JOIN cohorts source_cohort ON source_cohort.id = preset.source_cohort_id
      WHERE ${sqlTruthyExpr('preset.is_active', true)}
        AND (
          NOT EXISTS (
            SELECT 1
            FROM academic_v2_programs program
            WHERE program.legacy_program_id = preset.program_id
          )
          OR preset.source_cohort_id IS NULL
          OR source_cohort.id IS NULL
          OR NOT EXISTS (
            SELECT 1
            FROM academic_v2_cohorts cohort
            WHERE cohort.legacy_admission_id = source_cohort.legacy_admission_id
          )
        )
      ORDER BY preset.program_id ASC, preset.id ASC
      ${limitClause}
    `
  ));
}

async function listStaleLegacyOfferingRows(store, limit = null) {
  const normalizedLimit = Number.isInteger(Number(limit)) && Number(limit) > 0
    ? Math.max(1, Number(limit))
    : null;
  const limitClause = normalizedLimit ? `LIMIT ${normalizedLimit}` : '';
  return allRowsSafely(() => store.all(
    `
      SELECT
        offering.id,
        offering.title,
        offering.subject_catalog_id,
        offering.is_shared,
        offering.is_active,
        catalog.name AS catalog_name,
        COUNT(DISTINCT offering_context.study_context_id)::int AS context_count
      FROM subject_offerings offering
      LEFT JOIN subject_catalog catalog ON catalog.id = offering.subject_catalog_id
      LEFT JOIN subject_offering_contexts offering_context
        ON offering_context.subject_offering_id = offering.id
      LEFT JOIN academic_v2_groups g
        ON g.legacy_study_context_id = offering_context.study_context_id
      WHERE ${sqlTruthyExpr('offering.is_active', true)}
      GROUP BY offering.id, catalog.name
      HAVING COUNT(g.id) = 0
      ORDER BY offering.id ASC
      ${limitClause}
    `
  ));
}

async function buildCleanupAuditSummary(store) {
  const [
    usersWithoutGroupCount,
    usersWithCourseMismatchCount,
    groupsWithoutActiveTermCount,
    groupSubjectsWithoutTeacherCount,
    staleLegacyCourseRowsCount,
    staleLegacySubjectRowsCount,
    staleLegacySemesterRowsCount,
    staleLegacyScheduleRowsCount,
    staleStudyContextRows,
    staleProgramPresetRows,
    staleLegacyOfferingRows,
  ] = await Promise.all([
    getCountSafely(store,
      `
        SELECT COUNT(*)::int AS count
        FROM users
        WHERE role IN ('student', 'starosta')
          AND ${sqlTruthyExpr('is_active', true)}
          AND group_id IS NULL
      `
    ),
    getCountSafely(store,
      `
        SELECT COUNT(*)::int AS count
        FROM users u
        JOIN academic_v2_groups g ON g.id = u.group_id
        WHERE u.role IN ('student', 'starosta')
          AND ${sqlTruthyExpr('u.is_active', true)}
          AND g.legacy_course_id IS NOT NULL
          AND COALESCE(u.course_id, 0) <> g.legacy_course_id
      `
    ),
    getCountSafely(store,
      `
        SELECT COUNT(*)::int AS count
        FROM academic_v2_groups g
        WHERE NOT EXISTS (
          SELECT 1
          FROM academic_v2_terms term
          WHERE term.group_id = g.id
            AND ${sqlTruthyExpr('term.is_active', false)}
        )
      `
    ),
    getCountSafely(store,
      `
        SELECT COUNT(*)::int AS count
        FROM academic_v2_group_subjects subject
        WHERE NOT EXISTS (
          SELECT 1
          FROM academic_v2_teacher_assignments assignment
          WHERE assignment.group_subject_id = subject.id
        )
      `
    ),
    getCountSafely(store,
      `
        SELECT COUNT(*)::int AS count
        FROM (
          SELECT pac.admission_id, pac.course_id
          FROM program_admission_courses pac
          JOIN academic_v2_cohorts cohort ON cohort.legacy_admission_id = pac.admission_id
          WHERE NOT EXISTS (
            SELECT 1
            FROM academic_v2_groups g
            WHERE g.cohort_id = cohort.id
              AND g.legacy_course_id = pac.course_id
          )
          GROUP BY pac.admission_id, pac.course_id
        ) legacy_rows
      `
    ),
    getCountSafely(store,
      `
        SELECT COUNT(*)::int AS count
        FROM (
          SELECT sva.admission_id, sva.subject_id
          FROM subject_visibility_by_admission sva
          JOIN academic_v2_cohorts cohort ON cohort.legacy_admission_id = sva.admission_id
          WHERE NOT EXISTS (
            SELECT 1
            FROM academic_v2_groups g
            JOIN academic_v2_group_subjects subject ON subject.group_id = g.id
            WHERE g.cohort_id = cohort.id
              AND subject.legacy_subject_id = sva.subject_id
          )
          GROUP BY sva.admission_id, sva.subject_id
        ) legacy_rows
      `
    ),
    getCountSafely(store,
      `
        SELECT COUNT(*)::int AS count
        FROM semesters semester
        WHERE EXISTS (
          SELECT 1
          FROM academic_v2_groups g
          WHERE g.legacy_course_id = semester.course_id
        )
          AND NOT EXISTS (
            SELECT 1
            FROM academic_v2_terms term
            WHERE term.legacy_semester_id = semester.id
          )
      `
    ),
    getCountSafely(store,
      `
        SELECT COUNT(*)::int AS count
        FROM schedule_entries entry
        WHERE EXISTS (
          SELECT 1
          FROM academic_v2_groups g
          WHERE g.legacy_course_id = entry.course_id
        )
          AND NOT EXISTS (
            SELECT 1
            FROM academic_v2_schedule_entry_legacy_links projected
            WHERE projected.legacy_schedule_entry_id = entry.id
          )
      `
    ),
    listStaleStudyContextRows(store),
    listStaleProgramPresetRows(store),
    listStaleLegacyOfferingRows(store),
  ]);

  const summary = {
    users_without_group_id: Number(usersWithoutGroupCount || 0),
    users_with_course_projection_mismatch: Number(usersWithCourseMismatchCount || 0),
    groups_without_active_term: Number(groupsWithoutActiveTermCount || 0),
    group_subjects_without_teacher_assignment: Number(groupSubjectsWithoutTeacherCount || 0),
    stale_legacy_course_rows: Number(staleLegacyCourseRowsCount || 0),
    stale_legacy_subject_rows: Number(staleLegacySubjectRowsCount || 0),
    stale_legacy_semester_rows: Number(staleLegacySemesterRowsCount || 0),
    stale_legacy_schedule_rows: Number(staleLegacyScheduleRowsCount || 0),
    stale_legacy_study_context_rows: Array.isArray(staleStudyContextRows) ? staleStudyContextRows.length : 0,
    legacy_preset_rows: Array.isArray(staleProgramPresetRows) ? staleProgramPresetRows.length : 0,
    stale_legacy_offering_rows: Array.isArray(staleLegacyOfferingRows) ? staleLegacyOfferingRows.length : 0,
  };

  return {
    ...summary,
    total_findings: Object.values(summary).reduce((total, value) => total + Number(value || 0), 0),
  };
}

async function loadAcademicAuditSnapshot(store) {
  const [projectionHealth, auditSummary] = await Promise.all([
    listProjectionHealth(store),
    buildCleanupAuditSummary(store),
  ]);
  return {
    projectionHealth: projectionHealth.items,
    projectionHealthSummary: projectionHealth.summary,
    auditSummary,
  };
}

async function loadAcademicCleanupDetails(store, options = {}) {
  const limit = normalizeCleanupLimit(options.limit, 25, 200);
  const [
    usersWithoutGroupId,
    usersWithCourseProjectionMismatch,
    groupsWithoutActiveTerm,
    groupSubjectsWithoutTeacherAssignment,
    staleLegacyCourses,
    staleLegacySubjects,
    staleLegacySemesters,
    staleStudyContexts,
    staleProgramPresets,
    staleLegacyOfferings,
  ] = await Promise.all([
    store.all(
      `
        SELECT id, full_name, role, course_id, study_context_id
        FROM users
        WHERE role IN ('student', 'starosta')
          AND ${sqlTruthyExpr('is_active', true)}
          AND group_id IS NULL
        ORDER BY full_name ASC NULLS LAST, id ASC
        LIMIT ${limit}
      `
    ),
    store.all(
      `
        SELECT
          u.id,
          u.full_name,
          u.role,
          u.group_id,
          u.course_id,
          g.label AS group_label,
          g.legacy_course_id AS projected_course_id
        FROM users u
        JOIN academic_v2_groups g ON g.id = u.group_id
        WHERE u.role IN ('student', 'starosta')
          AND ${sqlTruthyExpr('u.is_active', true)}
          AND g.legacy_course_id IS NOT NULL
          AND COALESCE(u.course_id, 0) <> g.legacy_course_id
        ORDER BY u.id ASC
        LIMIT ${limit}
      `
    ),
    store.all(
      `
        SELECT
          g.id,
          g.label,
          g.stage_number,
          g.campus_key,
          c.id AS cohort_id,
          c.label AS cohort_label,
          p.name AS program_name
        FROM academic_v2_groups g
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        JOIN academic_v2_programs p ON p.id = c.program_id
        WHERE NOT EXISTS (
          SELECT 1
          FROM academic_v2_terms term
          WHERE term.group_id = g.id
            AND ${sqlTruthyExpr('term.is_active', false)}
        )
        ORDER BY p.name ASC, c.admission_year DESC, g.stage_number ASC, g.campus_key ASC, g.id ASC
        LIMIT ${limit}
      `
    ),
    store.all(
      `
        SELECT
          subject.id,
          subject.title,
          g.id AS group_id,
          g.label AS group_label,
          c.label AS cohort_label,
          p.name AS program_name
        FROM academic_v2_group_subjects subject
        JOIN academic_v2_groups g ON g.id = subject.group_id
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        JOIN academic_v2_programs p ON p.id = c.program_id
        WHERE NOT EXISTS (
          SELECT 1
          FROM academic_v2_teacher_assignments assignment
          WHERE assignment.group_subject_id = subject.id
        )
        ORDER BY p.name ASC, c.admission_year DESC, g.stage_number ASC, subject.sort_order ASC, subject.id ASC
        LIMIT ${limit}
      `
    ),
    store.all(
      `
        SELECT
          pac.admission_id,
          pac.course_id,
          cohort.id AS cohort_id,
          cohort.label AS cohort_label,
          program.name AS program_name,
          legacy_course.name AS legacy_course_name
        FROM program_admission_courses pac
        JOIN academic_v2_cohorts cohort ON cohort.legacy_admission_id = pac.admission_id
        JOIN academic_v2_programs program ON program.id = cohort.program_id
        LEFT JOIN courses legacy_course ON legacy_course.id = pac.course_id
        WHERE NOT EXISTS (
          SELECT 1
          FROM academic_v2_groups g
          WHERE g.cohort_id = cohort.id
            AND g.legacy_course_id = pac.course_id
        )
        ORDER BY program.name ASC, cohort.admission_year DESC, pac.course_id ASC
        LIMIT ${limit}
      `
    ),
    store.all(
      `
        SELECT
          sva.admission_id,
          sva.subject_id,
          cohort.id AS cohort_id,
          cohort.label AS cohort_label,
          program.name AS program_name,
          legacy_subject.name AS legacy_subject_name
        FROM subject_visibility_by_admission sva
        JOIN academic_v2_cohorts cohort ON cohort.legacy_admission_id = sva.admission_id
        JOIN academic_v2_programs program ON program.id = cohort.program_id
        LEFT JOIN subjects legacy_subject ON legacy_subject.id = sva.subject_id
        WHERE NOT EXISTS (
          SELECT 1
          FROM academic_v2_groups g
          JOIN academic_v2_group_subjects subject ON subject.group_id = g.id
          WHERE g.cohort_id = cohort.id
            AND subject.legacy_subject_id = sva.subject_id
        )
        ORDER BY program.name ASC, cohort.admission_year DESC, sva.subject_id ASC
        LIMIT ${limit}
      `
    ),
    store.all(
      `
        SELECT
          semester.id,
          semester.title,
          semester.course_id,
          legacy_course.name AS course_name
        FROM semesters semester
        LEFT JOIN courses legacy_course ON legacy_course.id = semester.course_id
        WHERE EXISTS (
          SELECT 1
          FROM academic_v2_groups g
          WHERE g.legacy_course_id = semester.course_id
        )
          AND NOT EXISTS (
            SELECT 1
            FROM academic_v2_terms term
            WHERE term.legacy_semester_id = semester.id
        )
        ORDER BY semester.course_id ASC, semester.id ASC
        LIMIT ${limit}
      `
    ),
    listStaleStudyContextRows(store, limit),
    listStaleProgramPresetRows(store, limit),
    listStaleLegacyOfferingRows(store, limit),
  ]);
  return {
    limit,
    usersWithoutGroupId,
    usersWithCourseProjectionMismatch,
    groupsWithoutActiveTerm,
    groupSubjectsWithoutTeacherAssignment,
    staleLegacyCourses,
    staleLegacySubjects,
    staleLegacySemesters,
    staleStudyContexts,
    staleProgramPresets,
    staleLegacyOfferings,
  };
}

function buildStageTemplateCards(termTemplates = [], subjectTemplates = [], currentStageNumber = 1) {
  return stageNumberList().map((stageNumber) => ({
    stage_number: stageNumber,
    term_count: (termTemplates || []).filter((item) => Number(item.stage_number || 0) === stageNumber).length,
    subject_count: (subjectTemplates || []).filter((item) => Number(item.stage_number || 0) === stageNumber).length,
    is_current: stageNumber === normalizeCourseStageNumber(currentStageNumber, 1),
  }));
}

function buildCohortPromotionPreview({
  cohort = null,
  program = null,
  groups = [],
  terms = [],
  groupSubjects = [],
  stageTermTemplates = [],
  stageSubjectTemplates = [],
  targetStageNumber = null,
} = {}) {
  if (!cohort || !program) {
    return null;
  }
  const currentStageNumber = normalizeCourseStageNumber(cohort.current_stage_number, 1);
  const resolvedTargetStageNumber = normalizeCourseStageNumber(
    targetStageNumber,
    currentStageNumber < 4 ? currentStageNumber + 1 : currentStageNumber
  );
  const sourceCourses = (groups || []).filter((item) => (
    Number(item.cohort_id || 0) === Number(cohort.id || 0)
    && normalizeCourseStageNumber(item.stage_number, 1) === currentStageNumber
    && item.is_active
  ));
  const targetCourses = (groups || []).filter((item) => (
    Number(item.cohort_id || 0) === Number(cohort.id || 0)
    && normalizeCourseStageNumber(item.stage_number, 1) === resolvedTargetStageNumber
  ));
  const templateTerms = (stageTermTemplates || []).filter((item) => (
    Number(item.program_id || 0) === Number(program.id || 0)
    && normalizeCourseStageNumber(item.stage_number, 1) === resolvedTargetStageNumber
  ));
  const templateSubjects = (stageSubjectTemplates || []).filter((item) => (
    Number(item.program_id || 0) === Number(program.id || 0)
    && normalizeCourseStageNumber(item.stage_number, 1) === resolvedTargetStageNumber
  ));
  const issues = [];
  if (resolvedTargetStageNumber === currentStageNumber) {
    issues.push('Target stage is already active.');
  }
  if (!sourceCourses.length) {
    issues.push('No active source courses exist for the cohort current stage.');
  }
  if (!templateTerms.length) {
    issues.push('Target stage template has no terms.');
  }
  if (!templateSubjects.length) {
    issues.push('Target stage template has no subjects.');
  }
  const coursePlans = sourceCourses.map((sourceCourse) => {
    const existingTargetCourse = targetCourses.find((item) => item.campus_key === sourceCourse.campus_key) || null;
    const sourceTerms = (terms || []).filter((item) => Number(item.group_id || 0) === Number(sourceCourse.id || 0));
    const sourceCourseSubjects = (groupSubjects || []).filter((item) => Number(item.group_id || 0) === Number(sourceCourse.id || 0));
    return {
      campus_key: sourceCourse.campus_key,
      source_course_id: Number(sourceCourse.id || 0),
      source_course_label: cleanText(sourceCourse.label, 160),
      source_term_count: sourceTerms.length,
      source_subject_count: sourceCourseSubjects.length,
      source_user_count: Number(sourceCourse.enrolled_users || 0),
      target_course_exists: Boolean(existingTargetCourse),
      target_course_id: existingTargetCourse ? Number(existingTargetCourse.id || 0) : null,
      target_course_label: existingTargetCourse ? cleanText(existingTargetCourse.label, 160) : '',
    };
  });
  return {
    cohort_id: Number(cohort.id || 0),
    cohort_label: cleanText(cohort.label, 160),
    program_id: Number(program.id || 0),
    program_name: cleanText(program.name, 160),
    current_stage_number: currentStageNumber,
    target_stage_number: resolvedTargetStageNumber,
    issues,
    can_apply: issues.length === 0,
    template_term_count: templateTerms.length,
    template_subject_count: templateSubjects.length,
    subjects_without_teacher_defaults: templateSubjects.filter((item) => !(item.teacher_ids || []).length).length,
    archive_term_count: coursePlans.reduce((sum, item) => sum + Number(item.source_term_count || 0), 0),
    archive_subject_count: coursePlans.reduce((sum, item) => sum + Number(item.source_subject_count || 0), 0),
    course_plans: coursePlans,
  };
}

function buildActivityIntegritySnapshot({
  stageSubjectTemplates = [],
  stageSubjectActivities = [],
  groupSubjects = [],
  groupSubjectActivities = [],
  groups = [],
  selectedProgramId = null,
  selectedTemplateStageNumber = 1,
  selectedGroupId = null,
} = {}) {
  const stageActivityCounts = new Map();
  const groupActivityCounts = new Map();
  const groupLabelsById = new Map(
    (Array.isArray(groups) ? groups : []).map((group) => [Number(group.id || 0), cleanText(group.label, 160)])
  );

  (Array.isArray(stageSubjectActivities) ? stageSubjectActivities : []).forEach((activity) => {
    const stageSubjectTemplateId = Number(activity && activity.stage_subject_template_id || 0);
    if (stageSubjectTemplateId > 0) {
      stageActivityCounts.set(stageSubjectTemplateId, Number(stageActivityCounts.get(stageSubjectTemplateId) || 0) + 1);
    }
  });
  (Array.isArray(groupSubjectActivities) ? groupSubjectActivities : []).forEach((activity) => {
    const groupSubjectId = Number(activity && activity.group_subject_id || 0);
    if (groupSubjectId > 0) {
      groupActivityCounts.set(groupSubjectId, Number(groupActivityCounts.get(groupSubjectId) || 0) + 1);
    }
  });

  const stageSubjectTemplatesWithoutActivities = (Array.isArray(stageSubjectTemplates) ? stageSubjectTemplates : [])
    .filter((item) => Number(stageActivityCounts.get(Number(item.id || 0)) || 0) < 1)
    .map((item) => ({
      ...item,
      id: Number(item.id || 0),
      program_id: Number(item.program_id || 0),
      stage_number: normalizeCourseStageNumber(item.stage_number, 1),
      subject_title: cleanText(item.title || item.subject_template_name, 160),
      activity_count: 0,
    }));

  const groupSubjectsWithoutActivities = (Array.isArray(groupSubjects) ? groupSubjects : [])
    .filter((item) => Number(groupActivityCounts.get(Number(item.id || 0)) || 0) < 1)
    .map((item) => ({
      ...item,
      id: Number(item.id || 0),
      group_id: Number(item.group_id || 0),
      group_label: cleanText(groupLabelsById.get(Number(item.group_id || 0)), 160),
      subject_title: cleanText(item.title || item.template_name, 160),
      activity_count: 0,
    }));

  const normalizedSelectedProgramId = Number(selectedProgramId || 0);
  const normalizedSelectedTemplateStageNumber = normalizeCourseStageNumber(selectedTemplateStageNumber, 1);
  const normalizedSelectedGroupId = Number(selectedGroupId || 0);

  return {
    summary: {
      stage_subject_templates_total: Array.isArray(stageSubjectTemplates) ? stageSubjectTemplates.length : 0,
      stage_subject_templates_without_activities: stageSubjectTemplatesWithoutActivities.length,
      group_subjects_total: Array.isArray(groupSubjects) ? groupSubjects.length : 0,
      group_subjects_without_activities: groupSubjectsWithoutActivities.length,
      scoped_stage_subject_templates_without_activities: stageSubjectTemplatesWithoutActivities.filter((item) => (
        normalizedSelectedProgramId > 0
        && Number(item.program_id || 0) === normalizedSelectedProgramId
        && normalizeCourseStageNumber(item.stage_number, 1) === normalizedSelectedTemplateStageNumber
      )).length,
      scoped_group_subjects_without_activities: groupSubjectsWithoutActivities.filter((item) => (
        normalizedSelectedGroupId > 0
        && Number(item.group_id || 0) === normalizedSelectedGroupId
      )).length,
    },
    scopedStageSubjectTemplatesWithoutActivities: stageSubjectTemplatesWithoutActivities.filter((item) => (
      normalizedSelectedProgramId > 0
      && Number(item.program_id || 0) === normalizedSelectedProgramId
      && normalizeCourseStageNumber(item.stage_number, 1) === normalizedSelectedTemplateStageNumber
    )),
    scopedGroupSubjectsWithoutActivities: groupSubjectsWithoutActivities.filter((item) => (
      normalizedSelectedGroupId > 0
      && Number(item.group_id || 0) === normalizedSelectedGroupId
    )),
  };
}

function buildAcademicSetupPageFallback(focus = {}, warning = '') {
  const programs = [];
  const cohorts = [];
  const groups = [];
  const terms = [];
  const resolvedFocus = buildFocusState(focus, {
    programs,
    cohorts,
    groups,
    terms,
  });
  const selectedTemplateStageNumber = normalizeCourseStageNumber(focus && focus.templateStageNumber, 1);
  return {
    summary: {
      programs_total: 0,
      cohorts_total: 0,
      groups_total: 0,
      terms_total: 0,
      templates_total: 0,
      group_subjects_total: 0,
      schedule_entries_total: 0,
      enrollments_total: 0,
    },
    programs,
    cohorts,
    groups,
    terms,
    subjectTemplates: [],
    stageTermTemplates: [],
    stageSubjectTemplates: [],
    stageSubjectActivities: [],
    groupSubjects: [],
    groupSubjectActivities: [],
    scheduleEntries: [],
    teachers: [],
    users: [],
    projectionHealth: [],
    projectionHealthSummary: {
      groups_total: 0,
      groups_healthy: 0,
      groups_with_issues: 0,
      groups_missing_legacy_course: 0,
      groups_without_terms: 0,
      groups_without_active_term: 0,
      groups_with_subject_projection_gaps: 0,
      groups_with_schedule_projection_gaps: 0,
      groups_with_user_sync_gaps: 0,
      subjects_without_teachers: 0,
    },
    activityIntegrity: {
      summary: {
        stage_subject_templates_total: 0,
        stage_subject_templates_without_activities: 0,
        group_subjects_total: 0,
        group_subjects_without_activities: 0,
        scoped_stage_subject_templates_without_activities: 0,
        scoped_group_subjects_without_activities: 0,
      },
      scopedStageSubjectTemplatesWithoutActivities: [],
      scopedGroupSubjectsWithoutActivities: [],
    },
    auditSummary: {
      users_without_group_id: 0,
      users_with_course_projection_mismatch: 0,
      groups_without_active_term: 0,
      group_subjects_without_teacher_assignment: 0,
      stale_legacy_course_rows: 0,
      stale_legacy_subject_rows: 0,
      stale_legacy_semester_rows: 0,
      stale_legacy_schedule_rows: 0,
      stale_legacy_study_context_rows: 0,
      legacy_preset_rows: 0,
      stale_legacy_offering_rows: 0,
      total_findings: 0,
    },
    renderWarnings: warning
      ? [{
          section: 'page',
          message: normalizeAcademicV2RenderMessage(warning),
        }]
      : [],
    selectedProgram: null,
    selectedCohort: null,
    selectedGroup: null,
    selectedTerm: null,
    selectedTemplateStageNumber,
    templateStageCards: buildStageTemplateCards([], [], 1),
    promotionPreview: null,
    focus: {
      ...resolvedFocus,
      templateStageNumber: selectedTemplateStageNumber,
    },
    scopedCohorts: [],
    scopedGroups: [],
    scopedTerms: [],
    scopedStageTermTemplates: [],
    scopedStageSubjectTemplates: [],
    scopedStageSubjectActivities: [],
    scopedGroupSubjects: [],
    scopedGroupSubjectActivities: [],
    scopedScheduleEntries: [],
  };
}

async function loadAcademicSetupPage(store, focus = {}, options = {}) {
  try {
    const settled = await Promise.allSettled([
      listPrograms(store),
      listCohorts(store),
      listGroups(store),
      listTerms(store),
      listSubjectTemplates(store),
      listProgramStageTermTemplates(store),
      listProgramStageSubjectTemplates(store),
      listProgramStageSubjectActivities(store),
      listGroupSubjects(store),
      listGroupSubjectActivities(store),
      listScheduleEntries(store),
      listTeacherOptions(store),
      listAssignableUsers(store),
      buildDashboardSummary(store),
      listProjectionHealth(store),
      buildCleanupAuditSummary(store),
    ]);
    const renderWarnings = [];
    const unwrap = (result, fallback, label) => {
      if (result.status === 'fulfilled') {
        return result.value;
      }
      renderWarnings.push({
        section: label,
        message: normalizeAcademicV2RenderMessage(
          result.reason && result.reason.message ? result.reason.message : result.reason
        ),
      });
      return fallback;
    };
    const programs = unwrap(settled[0], [], 'programs');
    const cohorts = unwrap(settled[1], [], 'cohorts');
    const groups = unwrap(settled[2], [], 'groups');
    const terms = unwrap(settled[3], [], 'terms');
    const subjectTemplates = unwrap(settled[4], [], 'subject templates');
    const stageTermTemplates = unwrap(settled[5], [], 'stage term templates');
    const stageSubjectTemplates = unwrap(settled[6], [], 'stage subject templates');
    const stageSubjectActivities = unwrap(settled[7], [], 'stage subject activities');
    const groupSubjects = unwrap(settled[8], [], 'group subjects');
    const groupSubjectActivities = unwrap(settled[9], [], 'group subject activities');
    const scheduleEntries = unwrap(settled[10], [], 'schedule entries');
    const teachers = unwrap(settled[11], [], 'teachers');
    const users = unwrap(settled[12], [], 'assignable users');
    const summary = unwrap(settled[13], {
      programs_total: 0,
      cohorts_total: 0,
      groups_total: 0,
      terms_total: 0,
      templates_total: 0,
      group_subjects_total: 0,
      schedule_entries_total: 0,
      enrollments_total: 0,
    }, 'dashboard summary');
    const projectionHealth = unwrap(settled[14], {
      items: [],
      summary: {
        groups_total: 0,
        groups_healthy: 0,
        groups_with_issues: 0,
        groups_missing_legacy_course: 0,
        groups_without_terms: 0,
        groups_without_active_term: 0,
        groups_with_subject_projection_gaps: 0,
        groups_with_schedule_projection_gaps: 0,
        groups_with_user_sync_gaps: 0,
        subjects_without_teachers: 0,
      },
    }, 'projection health');
    const auditSummary = unwrap(settled[15], {
      users_without_group_id: 0,
      users_with_course_projection_mismatch: 0,
      groups_without_active_term: 0,
      group_subjects_without_teacher_assignment: 0,
      stale_legacy_course_rows: 0,
      stale_legacy_subject_rows: 0,
      stale_legacy_semester_rows: 0,
      stale_legacy_schedule_rows: 0,
      stale_legacy_study_context_rows: 0,
      legacy_preset_rows: 0,
      stale_legacy_offering_rows: 0,
      total_findings: 0,
    }, 'cleanup audit');

    const resolvedFocus = buildFocusState(focus, {
      programs,
      cohorts,
      groups,
      terms,
    });

    const selectedProgram = programs.find((item) => Number(item.id) === Number(resolvedFocus.programId || 0)) || null;
    const selectedCohort = cohorts.find((item) => Number(item.id) === Number(resolvedFocus.cohortId || 0)) || null;
    const selectedGroup = groups.find((item) => Number(item.id) === Number(resolvedFocus.groupId || 0)) || null;
    const selectedTerm = terms.find((item) => Number(item.id) === Number(resolvedFocus.termId || 0)) || null;
    const selectedTemplateStageNumber = normalizeCourseStageNumber(
      focus.templateStageNumber,
      selectedGroup
        ? selectedGroup.stage_number
        : (selectedCohort ? selectedCohort.current_stage_number : 1)
    );
    const scopedStageTermTemplates = (stageTermTemplates || []).filter((item) => (
      Number(item.program_id || 0) === Number(selectedProgram && selectedProgram.id || 0)
      && normalizeCourseStageNumber(item.stage_number, 1) === selectedTemplateStageNumber
    ));
    const scopedStageSubjectTemplates = (stageSubjectTemplates || []).filter((item) => (
      Number(item.program_id || 0) === Number(selectedProgram && selectedProgram.id || 0)
      && normalizeCourseStageNumber(item.stage_number, 1) === selectedTemplateStageNumber
    ));
    const scopedStageSubjectActivities = (stageSubjectActivities || []).filter((item) => (
      Number(item.program_id || 0) === Number(selectedProgram && selectedProgram.id || 0)
      && normalizeCourseStageNumber(item.stage_number, 1) === selectedTemplateStageNumber
    ));
    const templateStageCards = buildStageTemplateCards(
      (stageTermTemplates || []).filter((item) => Number(item.program_id || 0) === Number(selectedProgram && selectedProgram.id || 0)),
      (stageSubjectTemplates || []).filter((item) => Number(item.program_id || 0) === Number(selectedProgram && selectedProgram.id || 0)),
      selectedCohort ? selectedCohort.current_stage_number : selectedTemplateStageNumber
    );
    const previewCohortId = normalizePositiveInt(options.previewCohortId);
    const previewTargetStageNumber = normalizePositiveInt(options.previewTargetStageNumber)
      ? normalizeCourseStageNumber(options.previewTargetStageNumber, 1)
      : null;
    const previewCohort = cohorts.find((item) => Number(item.id) === Number(previewCohortId || 0)) || null;
    const previewProgram = previewCohort
      ? (programs.find((item) => Number(item.id) === Number(previewCohort.program_id || 0)) || null)
      : null;
    const promotionPreview = buildCohortPromotionPreview({
      cohort: previewCohort,
      program: previewProgram,
      groups,
      terms,
      groupSubjects,
      stageTermTemplates,
      stageSubjectTemplates,
      targetStageNumber: previewTargetStageNumber,
    });
    const activityIntegrity = buildActivityIntegritySnapshot({
      stageSubjectTemplates,
      stageSubjectActivities,
      groupSubjects,
      groupSubjectActivities,
      groups,
      selectedProgramId: selectedProgram && selectedProgram.id,
      selectedTemplateStageNumber,
      selectedGroupId: selectedGroup && selectedGroup.id,
    });

    return {
      summary,
      programs,
      cohorts,
      groups,
      terms,
      subjectTemplates,
      stageTermTemplates,
      stageSubjectTemplates,
      stageSubjectActivities,
      groupSubjects,
      groupSubjectActivities,
      scheduleEntries,
      teachers,
      users,
      projectionHealth: projectionHealth.items,
      projectionHealthSummary: projectionHealth.summary,
      activityIntegrity,
      auditSummary,
      renderWarnings,
      selectedProgram,
      selectedCohort,
      selectedGroup,
      selectedTerm,
      selectedTemplateStageNumber,
      templateStageCards,
      promotionPreview,
      focus: {
        ...resolvedFocus,
        templateStageNumber: selectedTemplateStageNumber,
      },
      scopedCohorts: cohorts.filter((item) => Number(item.program_id) === Number(resolvedFocus.programId || 0)),
      scopedGroups: groups.filter((item) => Number(item.cohort_id) === Number(resolvedFocus.cohortId || 0)),
      scopedTerms: terms.filter((item) => Number(item.group_id) === Number(resolvedFocus.groupId || 0)),
      scopedStageTermTemplates,
      scopedStageSubjectTemplates,
      scopedStageSubjectActivities,
      scopedGroupSubjects: groupSubjects.filter((item) => Number(item.group_id) === Number(resolvedFocus.groupId || 0)),
      scopedGroupSubjectActivities: groupSubjectActivities.filter((item) => Number(item.group_id) === Number(resolvedFocus.groupId || 0)),
      scopedScheduleEntries: scheduleEntries.filter((item) => (
        Number(item.group_id) === Number(resolvedFocus.groupId || 0)
        && (!resolvedFocus.termId || Number(item.term_id) === Number(resolvedFocus.termId || 0))
      )),
    };
  } catch (err) {
    return buildAcademicSetupPageFallback(
      focus,
      err && err.message ? err.message : err
    );
  }
}

async function loadActivityIntegrityReport(store, focus = {}) {
  const [groups, stageSubjectTemplates, stageSubjectActivities, groupSubjects, groupSubjectActivities] = await Promise.all([
    listGroups(store),
    listProgramStageSubjectTemplates(store),
    listProgramStageSubjectActivities(store),
    listGroupSubjects(store),
    listGroupSubjectActivities(store),
  ]);
  return buildActivityIntegritySnapshot({
    stageSubjectTemplates,
    stageSubjectActivities,
    groupSubjects,
    groupSubjectActivities,
    groups,
    selectedProgramId: normalizePositiveInt(focus && (focus.programId || focus.program_id)),
    selectedTemplateStageNumber: normalizeCourseStageNumber(
      focus && (focus.templateStageNumber || focus.template_stage),
      1
    ),
    selectedGroupId: normalizePositiveInt(focus && (focus.groupId || focus.group_id)),
  });
}

async function withStoreTransaction(store, work) {
  if (store && typeof store.withTransaction === 'function') {
    return store.withTransaction(work);
  }
  return work(store);
}

async function getNextLegacyCourseId(tx) {
  const row = await tx.get('SELECT COALESCE(MAX(id), 0)::int + 1 AS next_id FROM courses');
  return Math.max(1, Number(row?.next_id || 1));
}

async function buildUniqueLegacyCourseName(tx, desiredName, existingCourseId = null) {
  const baseName = cleanText(desiredName, 160) || 'Imported group';
  let candidate = baseName;
  let suffix = 2;
  // Small tables, so simple conflict probing is enough.
  while (true) {
    const row = await tx.get(
      `
        SELECT id
        FROM courses
        WHERE LOWER(name) = LOWER(?)
        LIMIT 1
      `,
      [candidate]
    );
    if (!row || Number(row.id || 0) === Number(existingCourseId || 0)) {
      return candidate;
    }
    candidate = `${baseName} (${suffix})`;
    suffix += 1;
  }
}

async function ensureLegacyProgram(tx, programId) {
  const program = await tx.get(
    `
      SELECT id, track_key, code, name, sort_order, is_active, legacy_program_id
      FROM academic_v2_programs
      WHERE id = ?
      LIMIT 1
    `,
    [programId]
  );
  if (!program) {
    throw new Error('PROGRAM_NOT_FOUND');
  }
  const existingLegacyId = normalizePositiveInt(program.legacy_program_id);
  if (existingLegacyId) {
    await tx.run(
      `
        UPDATE study_programs
        SET
          track_key = ?,
          code = ?,
          name = ?,
          sort_order = ?,
          is_active = ?,
          updated_at = NOW()
        WHERE id = ?
      `,
      [
        normalizeTrackKey(program.track_key, 'bachelor'),
        cleanText(program.code, 40) || null,
        cleanText(program.name, 160),
        normalizeSortOrder(program.sort_order, 100),
        normalizeBoolean(program.is_active, true),
        existingLegacyId,
      ]
    );
    return existingLegacyId;
  }
  const existingByName = await tx.get(
    `
      SELECT id
      FROM study_programs
      WHERE track_key = ?
        AND LOWER(name) = LOWER(?)
      LIMIT 1
    `,
    [normalizeTrackKey(program.track_key, 'bachelor'), cleanText(program.name, 160)]
  );
  let legacyProgramId = normalizePositiveInt(existingByName && existingByName.id);
  if (!legacyProgramId) {
    const inserted = await tx.get(
      `
        INSERT INTO study_programs
          (track_key, code, name, sort_order, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, NOW(), NOW())
        RETURNING id
      `,
      [
        normalizeTrackKey(program.track_key, 'bachelor'),
        cleanText(program.code, 40) || null,
        cleanText(program.name, 160),
        normalizeSortOrder(program.sort_order, 100),
        normalizeBoolean(program.is_active, true),
      ]
    );
    legacyProgramId = normalizePositiveInt(inserted && inserted.id);
  } else {
    await tx.run(
      `
        UPDATE study_programs
        SET
          code = ?,
          name = ?,
          sort_order = ?,
          is_active = ?,
          updated_at = NOW()
        WHERE id = ?
      `,
      [
        cleanText(program.code, 40) || null,
        cleanText(program.name, 160),
        normalizeSortOrder(program.sort_order, 100),
        normalizeBoolean(program.is_active, true),
        legacyProgramId,
      ]
    );
  }
  await tx.run(
    'UPDATE academic_v2_programs SET legacy_program_id = ?, updated_at = NOW() WHERE id = ?',
    [legacyProgramId, program.id]
  );
  return legacyProgramId;
}

async function ensureLegacyAdmission(tx, cohortId) {
  const cohort = await tx.get(
    `
      SELECT id, program_id, admission_year, label, is_active, legacy_admission_id
      FROM academic_v2_cohorts
      WHERE id = ?
      LIMIT 1
    `,
    [cohortId]
  );
  if (!cohort) {
    throw new Error('COHORT_NOT_FOUND');
  }
  const legacyProgramId = await ensureLegacyProgram(tx, Number(cohort.program_id));
  const existingLegacyId = normalizePositiveInt(cohort.legacy_admission_id);
  if (existingLegacyId) {
    await tx.run(
      `
        UPDATE program_admissions
        SET
          program_id = ?,
          admission_year = ?,
          label = ?,
          is_active = ?,
          updated_at = NOW()
        WHERE id = ?
      `,
      [
        legacyProgramId,
        Number(cohort.admission_year || new Date().getUTCFullYear()),
        cleanText(cohort.label, 120) || `Cohort ${Number(cohort.admission_year || new Date().getUTCFullYear())}`,
        normalizeBoolean(cohort.is_active, true),
        existingLegacyId,
      ]
    );
    return existingLegacyId;
  }
  const existingByKey = await tx.get(
    `
      SELECT id
      FROM program_admissions
      WHERE program_id = ?
        AND admission_year = ?
      LIMIT 1
    `,
    [legacyProgramId, Number(cohort.admission_year || new Date().getUTCFullYear())]
  );
  let legacyAdmissionId = normalizePositiveInt(existingByKey && existingByKey.id);
  if (!legacyAdmissionId) {
    const inserted = await tx.get(
      `
        INSERT INTO program_admissions
          (program_id, admission_year, label, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, NOW(), NOW())
        RETURNING id
      `,
      [
        legacyProgramId,
        Number(cohort.admission_year || new Date().getUTCFullYear()),
        cleanText(cohort.label, 120) || `Cohort ${Number(cohort.admission_year || new Date().getUTCFullYear())}`,
        normalizeBoolean(cohort.is_active, true),
      ]
    );
    legacyAdmissionId = normalizePositiveInt(inserted && inserted.id);
  } else {
    await tx.run(
      `
        UPDATE program_admissions
        SET
          label = ?,
          is_active = ?,
          updated_at = NOW()
        WHERE id = ?
      `,
      [
        cleanText(cohort.label, 120) || `Cohort ${Number(cohort.admission_year || new Date().getUTCFullYear())}`,
        normalizeBoolean(cohort.is_active, true),
        legacyAdmissionId,
      ]
    );
  }
  await tx.run(
    'UPDATE academic_v2_cohorts SET legacy_admission_id = ?, updated_at = NOW() WHERE id = ?',
    [legacyAdmissionId, cohort.id]
  );
  return legacyAdmissionId;
}

async function ensureLegacyCourse(tx, groupId) {
  const group = await tx.get(
    `
      SELECT
        g.id,
        g.cohort_id,
        g.stage_number,
        g.campus_key,
        g.label,
        g.is_active,
        g.legacy_course_id,
        c.program_id,
        p.track_key
      FROM academic_v2_groups g
      JOIN academic_v2_cohorts c ON c.id = g.cohort_id
      JOIN academic_v2_programs p ON p.id = c.program_id
      WHERE g.id = ?
      LIMIT 1
    `,
    [groupId]
  );
  if (!group) {
    throw new Error('GROUP_NOT_FOUND');
  }
  const teacherCourse = normalizeTrackKey(group.track_key, 'bachelor') === 'teacher';
  const existingLegacyCourseId = normalizePositiveInt(group.legacy_course_id);
  const courseName = await buildUniqueLegacyCourseName(tx, cleanText(group.label, 160), existingLegacyCourseId);
  let legacyCourseId = existingLegacyCourseId;
  if (!legacyCourseId) {
    legacyCourseId = await getNextLegacyCourseId(tx);
    await tx.run(
      `
        INSERT INTO courses (id, name, is_teacher_course, location)
        VALUES (?, ?, ?, ?)
      `,
      [legacyCourseId, courseName, teacherCourse, normalizeCampusKey(group.campus_key, 'kyiv')]
    );
    await tx.run(
      'UPDATE academic_v2_groups SET legacy_course_id = ?, updated_at = NOW() WHERE id = ?',
      [legacyCourseId, group.id]
    );
  } else {
    await tx.run(
      `
        UPDATE courses
        SET
          name = ?,
          is_teacher_course = ?,
          location = ?
        WHERE id = ?
      `,
      [courseName, teacherCourse, normalizeCampusKey(group.campus_key, 'kyiv'), legacyCourseId]
    );
  }

  const legacyAdmissionId = await ensureLegacyAdmission(tx, Number(group.cohort_id));
  await tx.run(
    `
      INSERT INTO program_admission_courses
        (admission_id, course_id, is_visible, created_at, updated_at)
      VALUES (?, ?, ?, NOW(), NOW())
      ON CONFLICT (admission_id, course_id)
      DO UPDATE SET
        is_visible = EXCLUDED.is_visible,
        updated_at = NOW()
    `,
    [legacyAdmissionId, legacyCourseId, normalizeBoolean(group.is_active, true)]
  );

  return {
    legacyCourseId,
    legacyAdmissionId,
    group,
  };
}

async function ensureLegacyTerm(tx, termId) {
  const term = await tx.get(
    `
      SELECT id, group_id, term_number, title, start_date, weeks_count, is_active, is_archived, legacy_semester_id
      FROM academic_v2_terms
      WHERE id = ?
      LIMIT 1
    `,
    [termId]
  );
  if (!term) {
    throw new Error('TERM_NOT_FOUND');
  }
  const { legacyCourseId } = await ensureLegacyCourse(tx, Number(term.group_id));
  const startDate = normalizeDateString(term.start_date, new Date().toISOString().slice(0, 10));
  const existingLegacySemesterId = normalizePositiveInt(term.legacy_semester_id);
  let legacySemesterId = existingLegacySemesterId;
  if (!legacySemesterId) {
    const inserted = await tx.get(
      `
        INSERT INTO semesters
          (course_id, title, start_date, weeks_count, is_active, is_archived)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING id
      `,
      [
        legacyCourseId,
        cleanText(term.title, 120) || `Term ${Number(term.term_number || 1)}`,
        startDate,
        normalizeWeeksCount(term.weeks_count, 16),
        normalizeLegacyBinaryFlag(term.is_active, false),
        normalizeLegacyBinaryFlag(term.is_archived, false),
      ]
    );
    legacySemesterId = normalizePositiveInt(inserted && inserted.id);
    await tx.run(
      'UPDATE academic_v2_terms SET legacy_semester_id = ?, updated_at = NOW() WHERE id = ?',
      [legacySemesterId, term.id]
    );
  } else {
    await tx.run(
      `
        UPDATE semesters
        SET
          course_id = ?,
          title = ?,
          start_date = ?,
          weeks_count = ?,
          is_active = ?,
          is_archived = ?
        WHERE id = ?
      `,
      [
        legacyCourseId,
        cleanText(term.title, 120) || `Term ${Number(term.term_number || 1)}`,
        startDate,
        normalizeWeeksCount(term.weeks_count, 16),
        normalizeLegacyBinaryFlag(term.is_active, false),
        normalizeLegacyBinaryFlag(term.is_archived, false),
        legacySemesterId,
      ]
    );
  }

  if (normalizeBoolean(term.is_active, false)) {
    await tx.run(
      `
        UPDATE academic_v2_terms
        SET is_active = CASE WHEN id = ? THEN TRUE ELSE FALSE END,
            updated_at = NOW()
        WHERE group_id = ?
      `,
      [term.id, term.group_id]
    );
    await tx.run(
      `
        UPDATE semesters
        SET is_active = CASE WHEN id = ? THEN 1 ELSE 0 END
        WHERE course_id = ?
      `,
      [legacySemesterId, legacyCourseId]
    );
  }

  return {
    legacySemesterId,
    legacyCourseId,
    term,
  };
}

async function ensureLegacySubject(tx, groupSubjectId) {
  const groupSubject = await tx.get(
    `
      SELECT
        gs.*,
        st.name AS template_name,
        st.legacy_catalog_id
      FROM academic_v2_group_subjects gs
      JOIN academic_v2_subject_templates st ON st.id = gs.subject_template_id
      WHERE gs.id = ?
      LIMIT 1
    `,
    [groupSubjectId]
  );
  if (!groupSubject) {
    throw new Error('GROUP_SUBJECT_NOT_FOUND');
  }
  const { legacyCourseId, legacyAdmissionId } = await ensureLegacyCourse(tx, Number(groupSubject.group_id));
  const existingLegacySubjectId = normalizePositiveInt(groupSubject.legacy_subject_id);
  let legacySubjectId = existingLegacySubjectId;
  if (!legacySubjectId) {
    const inserted = await tx.get(
      `
        INSERT INTO subjects
          (name, group_count, default_group, show_in_teamwork, visible, is_required, is_general, course_id, catalog_id, is_shared)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, FALSE)
        RETURNING id
      `,
      [
        cleanText(groupSubject.title || groupSubject.template_name, 160),
        Math.max(1, Number(groupSubject.group_count || 0) || 1),
        Math.max(1, Number(groupSubject.default_group || 0) || 1),
        normalizeBoolean(groupSubject.show_in_teamwork, true) ? 1 : 0,
        normalizeBoolean(groupSubject.is_visible, true) ? 1 : 0,
        normalizeBoolean(groupSubject.is_required, true),
        normalizeBoolean(groupSubject.is_general, true),
        legacyCourseId,
        normalizePositiveInt(groupSubject.legacy_catalog_id),
      ]
    );
    legacySubjectId = normalizePositiveInt(inserted && inserted.id);
    await tx.run(
      'UPDATE academic_v2_group_subjects SET legacy_subject_id = ?, updated_at = NOW() WHERE id = ?',
      [legacySubjectId, groupSubject.id]
    );
  } else {
    await tx.run(
      `
        UPDATE subjects
        SET
          name = ?,
          group_count = ?,
          default_group = ?,
          show_in_teamwork = ?,
          visible = ?,
          is_required = ?,
          is_general = ?,
          course_id = ?,
          catalog_id = ?,
          is_shared = FALSE
        WHERE id = ?
      `,
      [
        cleanText(groupSubject.title || groupSubject.template_name, 160),
        Math.max(1, Number(groupSubject.group_count || 0) || 1),
        Math.max(1, Number(groupSubject.default_group || 0) || 1),
        normalizeBoolean(groupSubject.show_in_teamwork, true) ? 1 : 0,
        normalizeBoolean(groupSubject.is_visible, true) ? 1 : 0,
        normalizeBoolean(groupSubject.is_required, true),
        normalizeBoolean(groupSubject.is_general, true),
        legacyCourseId,
        normalizePositiveInt(groupSubject.legacy_catalog_id),
        legacySubjectId,
      ]
    );
  }

  await tx.run(
    `
      INSERT INTO subject_course_bindings (subject_id, course_id, created_at, updated_at)
      VALUES (?, ?, NOW(), NOW())
      ON CONFLICT (subject_id, course_id)
      DO UPDATE SET updated_at = NOW()
    `,
    [legacySubjectId, legacyCourseId]
  );
  await tx.run(
    `
      INSERT INTO subject_visibility_by_admission
        (admission_id, subject_id, is_visible, created_at, updated_at)
      VALUES (?, ?, ?, NOW(), NOW())
      ON CONFLICT (admission_id, subject_id)
      DO UPDATE SET
        is_visible = EXCLUDED.is_visible,
        updated_at = NOW()
    `,
    [legacyAdmissionId, legacySubjectId, normalizeBoolean(groupSubject.is_visible, true)]
  );

  return {
    legacySubjectId,
    legacyCourseId,
    legacyAdmissionId,
    groupSubject,
  };
}

async function deleteLegacyScheduleProjectionForEntryTx(tx, scheduleEntryId) {
  const links = await tx.all(
    `
      SELECT legacy_schedule_entry_id
      FROM academic_v2_schedule_entry_legacy_links
      WHERE schedule_entry_id = ?
      ORDER BY group_number ASC, id ASC
    `,
    [normalizePositiveInt(scheduleEntryId)]
  );
  for (const link of links || []) {
    const legacyScheduleEntryId = normalizePositiveInt(link.legacy_schedule_entry_id);
    if (legacyScheduleEntryId) {
      await tx.run('DELETE FROM schedule_entries WHERE id = ?', [legacyScheduleEntryId]);
    }
  }
  await tx.run('DELETE FROM academic_v2_schedule_entry_legacy_links WHERE schedule_entry_id = ?', [normalizePositiveInt(scheduleEntryId)]);
  await tx.run(
    `
      UPDATE academic_v2_schedule_entries
      SET legacy_schedule_entry_id = NULL,
          updated_at = NOW()
      WHERE id = ?
    `,
    [normalizePositiveInt(scheduleEntryId)]
  );
}

async function deleteScheduleRowsForGroupSubjectTx(tx, groupSubjectId) {
  const rows = await tx.all(
    'SELECT id FROM academic_v2_schedule_entries WHERE group_subject_id = ? ORDER BY id ASC',
    [normalizePositiveInt(groupSubjectId)]
  );
  for (const row of rows || []) {
    await deleteLegacyScheduleProjectionForEntryTx(tx, row.id);
  }
  await tx.run('DELETE FROM academic_v2_schedule_entries WHERE group_subject_id = ?', [normalizePositiveInt(groupSubjectId)]);
}

async function deleteScheduleRowsForActivityTx(tx, groupSubjectActivityId) {
  const rows = await tx.all(
    'SELECT id FROM academic_v2_schedule_entries WHERE group_subject_activity_id = ? ORDER BY id ASC',
    [normalizePositiveInt(groupSubjectActivityId)]
  );
  for (const row of rows || []) {
    await deleteLegacyScheduleProjectionForEntryTx(tx, row.id);
  }
  await tx.run('DELETE FROM academic_v2_schedule_entries WHERE group_subject_activity_id = ?', [normalizePositiveInt(groupSubjectActivityId)]);
}

async function deleteScheduleRowsForTermTx(tx, termId) {
  const rows = await tx.all(
    'SELECT id FROM academic_v2_schedule_entries WHERE term_id = ? ORDER BY id ASC',
    [normalizePositiveInt(termId)]
  );
  for (const row of rows || []) {
    await deleteLegacyScheduleProjectionForEntryTx(tx, row.id);
  }
}

async function syncScheduleProjectionForGroup(tx, groupId) {
  const scheduleEntries = await tx.all(
    `
      SELECT
        se.id,
        se.group_subject_id,
        se.group_subject_activity_id,
        se.term_id,
        se.group_number,
        se.target_group_numbers,
        se.day_of_week,
        se.class_number,
        se.week_number,
        se.lesson_type,
        activity.activity_type,
        gs.group_count
      FROM academic_v2_schedule_entries se
      JOIN academic_v2_group_subject_activities activity ON activity.id = se.group_subject_activity_id
      JOIN academic_v2_group_subjects gs ON gs.id = activity.group_subject_id
      WHERE gs.group_id = ?
      ORDER BY se.id ASC
    `,
    [groupId]
  );
  for (const entry of scheduleEntries || []) {
    const activityType = normalizeActivityType(entry.activity_type || entry.lesson_type, 'lecture');
    const targetGroupNumbers = deriveScheduleTargetGroups(
      activityType,
      entry.target_group_numbers || [],
      entry.group_number,
      entry.group_count
    );
    const projectionTargetGroups = activityType === 'lecture'
      ? [1]
      : targetGroupNumbers;
    const primaryGroupNumber = deriveScheduleGroupNumber(activityType, targetGroupNumbers, entry.group_number);
    const { legacySubjectId, legacyCourseId } = await ensureLegacySubject(tx, Number(entry.group_subject_id));
    const { legacySemesterId } = await ensureLegacyTerm(tx, Number(entry.term_id));
    const existingLinks = await tx.all(
      `
        SELECT id, group_number, legacy_schedule_entry_id
        FROM academic_v2_schedule_entry_legacy_links
        WHERE schedule_entry_id = ?
        ORDER BY group_number ASC, id ASC
      `,
      [entry.id]
    );
    const existingByGroupNumber = new Map();
    for (const link of existingLinks || []) {
      existingByGroupNumber.set(Number(link.group_number || 0), link);
    }
    const syncedLegacyIds = [];

    for (const groupNumber of projectionTargetGroups) {
      const legacyGroupNumber = Math.max(1, Number(groupNumber || 0) || 1);
      const existingLink = existingByGroupNumber.get(legacyGroupNumber) || null;
      let legacyScheduleEntryId = normalizePositiveInt(existingLink && existingLink.legacy_schedule_entry_id);
      if (!legacyScheduleEntryId) {
        const inserted = await tx.get(
          `
            INSERT INTO schedule_entries
              (subject_id, group_number, day_of_week, class_number, week_number, course_id, semester_id, lesson_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id
          `,
          [
            legacySubjectId,
            legacyGroupNumber,
            normalizeDayOfWeek(entry.day_of_week, 'Monday'),
            Math.max(1, Number(entry.class_number || 0) || 1),
            Math.max(1, Number(entry.week_number || 0) || 1),
            legacyCourseId,
            legacySemesterId,
            activityType,
          ]
        );
        legacyScheduleEntryId = normalizePositiveInt(inserted && inserted.id);
      } else {
        await tx.run(
          `
            UPDATE schedule_entries
            SET
              subject_id = ?,
              group_number = ?,
              day_of_week = ?,
              class_number = ?,
              week_number = ?,
              course_id = ?,
              semester_id = ?,
              lesson_type = ?
            WHERE id = ?
          `,
          [
            legacySubjectId,
            legacyGroupNumber,
            normalizeDayOfWeek(entry.day_of_week, 'Monday'),
            Math.max(1, Number(entry.class_number || 0) || 1),
            Math.max(1, Number(entry.week_number || 0) || 1),
            legacyCourseId,
            legacySemesterId,
            activityType,
            legacyScheduleEntryId,
          ]
        );
      }
      syncedLegacyIds.push(legacyScheduleEntryId);
      await tx.run(
        `
          INSERT INTO academic_v2_schedule_entry_legacy_links
            (schedule_entry_id, group_number, legacy_schedule_entry_id, created_at, updated_at)
          VALUES (?, ?, ?, NOW(), NOW())
          ON CONFLICT (schedule_entry_id, group_number)
          DO UPDATE SET
            legacy_schedule_entry_id = EXCLUDED.legacy_schedule_entry_id,
            updated_at = NOW()
        `,
        [entry.id, legacyGroupNumber, legacyScheduleEntryId]
      );
      existingByGroupNumber.delete(legacyGroupNumber);
    }

    for (const staleLink of existingByGroupNumber.values()) {
      const staleLegacyScheduleEntryId = normalizePositiveInt(staleLink.legacy_schedule_entry_id);
      if (staleLegacyScheduleEntryId) {
        await tx.run('DELETE FROM schedule_entries WHERE id = ?', [staleLegacyScheduleEntryId]);
      }
      await tx.run('DELETE FROM academic_v2_schedule_entry_legacy_links WHERE id = ?', [staleLink.id]);
    }

    await tx.run(
      `
        UPDATE academic_v2_schedule_entries
        SET
          lesson_type = ?,
          group_number = ?,
          legacy_schedule_entry_id = ?,
          updated_at = NOW()
        WHERE id = ?
      `,
      [
        activityType,
        primaryGroupNumber,
        normalizePositiveInt(syncedLegacyIds[0]),
        entry.id,
      ]
    );
  }
}

async function syncUserAssignmentsForGroup(tx, groupId) {
  const group = await tx.get(
    `
      SELECT
        g.id,
        g.cohort_id,
        g.legacy_course_id,
        p.track_key,
        c.program_id,
        c.legacy_admission_id
      FROM academic_v2_groups g
      JOIN academic_v2_cohorts c ON c.id = g.cohort_id
      JOIN academic_v2_programs p ON p.id = c.program_id
      WHERE g.id = ?
      LIMIT 1
    `,
    [groupId]
  );
  if (!group) {
    return;
  }
  const legacyCourseId = normalizePositiveInt(group.legacy_course_id) || (await ensureLegacyCourse(tx, groupId)).legacyCourseId;
  const enrollments = await tx.all(
    `
      SELECT user_id
      FROM academic_v2_student_enrollments
      WHERE group_id = ?
    `,
    [groupId]
  );
  for (const row of enrollments || []) {
    const userId = normalizePositiveInt(row.user_id);
    if (!userId) continue;
    await tx.run(
      `
        UPDATE users
        SET
          group_id = ?,
          course_id = ?,
          study_program_id = ?,
          admission_id = ?,
          study_track = ?
        WHERE id = ?
      `,
      [
        groupId,
        legacyCourseId,
        normalizePositiveInt(group.program_id),
        normalizePositiveInt(group.legacy_admission_id),
        normalizeTrackKey(group.track_key, 'bachelor'),
        userId,
      ]
    );
  }
}

async function syncGroupProjection(tx, groupId) {
  const { legacyCourseId } = await ensureLegacyCourse(tx, groupId);
  const terms = await tx.all('SELECT id FROM academic_v2_terms WHERE group_id = ? ORDER BY term_number ASC', [groupId]);
  for (const term of terms || []) {
    await ensureLegacyTerm(tx, Number(term.id));
  }
  const subjects = await tx.all('SELECT id FROM academic_v2_group_subjects WHERE group_id = ? ORDER BY sort_order ASC, id ASC', [groupId]);
  for (const subject of subjects || []) {
    await ensureLegacySubject(tx, Number(subject.id));
  }
  await syncScheduleProjectionForGroup(tx, groupId);
  await syncUserAssignmentsForGroup(tx, groupId);
  return { legacyCourseId };
}

async function runProjectionSyncSafely(store, groupIds = [], logContext = 'academicV2.projection') {
  const normalizedGroupIds = Array.from(new Set(
    (Array.isArray(groupIds) ? groupIds : [groupIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  if (!normalizedGroupIds.length) {
    return {};
  }
  const failedGroupIds = [];
  for (const groupId of normalizedGroupIds) {
    try {
      await resyncGroupProjection(store, groupId);
    } catch (err) {
      failedGroupIds.push(groupId);
      console.error(`${logContext}.projection`, { groupId, error: err });
    }
  }
  if (!failedGroupIds.length) {
    return {};
  }
  return {
    warningMessageKey: 'projectionSyncDeferred',
    warningGroupIds: failedGroupIds,
  };
}

function isAcademicV2GroupWriteConflictError(err) {
  if (String(err?.code || '').trim() !== '23505') {
    return false;
  }
  const constraint = String(err?.constraint || '').trim().toLowerCase();
  const message = String(err?.message || '').trim().toLowerCase();
  return constraint.includes('academic_v2_groups')
    || (message.includes('academic_v2_groups') && message.includes('duplicate'));
}

function getAcademicV2GroupWriteErrorMeta(err) {
  return {
    code: String(err?.code || '').trim().toUpperCase(),
    constraint: String(err?.constraint || '').trim().toLowerCase(),
    message: String(err?.message || '').trim().toLowerCase(),
    detail: String(err?.detail || '').trim().toLowerCase(),
  };
}

function isAcademicV2GroupWriteError(err) {
  const meta = getAcademicV2GroupWriteErrorMeta(err);
  if (!meta.code) {
    return false;
  }
  return meta.constraint.includes('academic_v2_groups')
    || meta.message.includes('academic_v2_groups')
    || meta.detail.includes('academic_v2_groups')
    || (
      ['23502', '23503', '23505', '23514', '22001', '22P02', '40001', '40P01'].includes(meta.code)
      && (
        meta.constraint.includes('cohort')
        || meta.constraint.includes('legacy_course')
        || meta.constraint.includes('legacy_study_context')
        || meta.message.includes('cohort_id')
        || meta.message.includes('stage_number')
        || meta.message.includes('campus_key')
        || meta.message.includes('legacy_course_id')
        || meta.message.includes('legacy_study_context_id')
        || meta.message.includes('label')
        || meta.detail.includes('cohort_id')
        || meta.detail.includes('stage_number')
        || meta.detail.includes('campus_key')
        || meta.detail.includes('legacy_course_id')
        || meta.detail.includes('legacy_study_context_id')
        || meta.detail.includes('label')
      )
    );
}

function isAcademicV2GroupLabelConflictError(err) {
  const meta = getAcademicV2GroupWriteErrorMeta(err);
  if (meta.code !== '23505') {
    return false;
  }
  return meta.constraint.includes('cohort_id_stage_number_campus_key_label')
    || (
      (meta.message.includes('duplicate') || meta.detail.includes('already exists'))
      && meta.detail.includes('cohort_id')
      && meta.detail.includes('stage_number')
      && meta.detail.includes('campus_key')
      && meta.detail.includes('label')
    );
}

function isAcademicV2GroupInvalidInputError(err) {
  const meta = getAcademicV2GroupWriteErrorMeta(err);
  if (!['22001', '22P02', '23502', '23514'].includes(meta.code)) {
    return false;
  }
  return isAcademicV2GroupWriteError(err);
}

function isAcademicV2GroupRetryableWriteError(err) {
  const meta = getAcademicV2GroupWriteErrorMeta(err);
  return ['40001', '40P01'].includes(meta.code);
}

function isAcademicV2GroupSchemaCompatibilityError(err) {
  const meta = getAcademicV2GroupWriteErrorMeta(err);
  if (!['42P01', '42703', '42P10', '42883', '42804'].includes(meta.code)) {
    return false;
  }
  return isAcademicV2GroupWriteError(err)
    || meta.message.includes('academic_v2_groups')
    || meta.detail.includes('academic_v2_groups');
}

function normalizeAcademicV2GroupSaveErrorKey(err) {
  const errorKey = String(err?.message || '').trim();
  if ([
    'COHORT_REQUIRED',
    'COHORT_NOT_FOUND',
    'GROUP_LABEL_REQUIRED',
    'GROUP_NOT_FOUND',
    'COURSE_STAGE_CAMPUS_DUPLICATE',
    'GROUP_LABEL_DUPLICATE',
    'GROUP_INVALID',
    'GROUP_SAVE_RETRY',
    'ACADEMIC_V2_SCHEMA_INCOMPATIBLE',
    'GROUP_SAVE_FAILED',
  ].includes(errorKey)) {
    return errorKey;
  }
  if (isAcademicV2GroupCohortForeignKeyError(err)) {
    return 'COHORT_NOT_FOUND';
  }
  if (isAcademicV2GroupLabelConflictError(err)) {
    return 'GROUP_LABEL_DUPLICATE';
  }
  if (isAcademicV2GroupInvalidInputError(err)) {
    return 'GROUP_INVALID';
  }
  if (isAcademicV2GroupRetryableWriteError(err)) {
    return 'GROUP_SAVE_RETRY';
  }
  if (isAcademicV2SchemaCompatibilityError(err)) {
    return 'ACADEMIC_V2_SCHEMA_INCOMPATIBLE';
  }
  if (isAcademicV2GroupSchemaCompatibilityError(err)) {
    return 'ACADEMIC_V2_SCHEMA_INCOMPATIBLE';
  }
  if (isAcademicV2GroupWriteConflictError(err) || isAcademicV2GroupWriteError(err)) {
    return 'GROUP_SAVE_FAILED';
  }
  return '';
}

function isAcademicV2GroupCohortForeignKeyError(err) {
  if (String(err?.code || '').trim() !== '23503') {
    return false;
  }
  const constraint = String(err?.constraint || '').trim().toLowerCase();
  const message = String(err?.message || '').trim().toLowerCase();
  return constraint.includes('academic_v2_groups')
    || (message.includes('academic_v2_groups') && message.includes('cohort_id'));
}

async function assertUniqueStageCampusCourse(tx, {
  groupId = null,
  cohortId = null,
  stageNumber = 1,
  campusKey = 'kyiv',
} = {}) {
  const normalizedGroupId = normalizePositiveInt(groupId);
  const duplicate = await tx.get(
    `
      SELECT id
      FROM academic_v2_groups
      WHERE cohort_id = ?
        AND stage_number = ?
        AND campus_key = ?
        ${normalizedGroupId ? 'AND id <> ?' : ''}
      ORDER BY id ASC
      LIMIT 1
    `,
    [
      normalizePositiveInt(cohortId),
      normalizeCourseStageNumber(stageNumber, 1),
      normalizeCampusKey(campusKey, 'kyiv'),
      ...(normalizedGroupId ? [normalizedGroupId] : []),
    ]
  );
  if (duplicate) {
    throw new Error('COURSE_STAGE_CAMPUS_DUPLICATE');
  }
}

async function ensureProgramStageTemplate(tx, programId, stageNumber) {
  const normalizedProgramId = normalizePositiveInt(programId);
  const normalizedStageNumber = normalizeCourseStageNumber(stageNumber, 1);
  if (!normalizedProgramId) {
    throw new Error('PROGRAM_REQUIRED');
  }
  let row = await tx.get(
    `
      SELECT *
      FROM academic_v2_program_stage_templates
      WHERE program_id = ?
        AND stage_number = ?
      LIMIT 1
    `,
    [normalizedProgramId, normalizedStageNumber]
  );
  if (row) {
    return row;
  }
  row = await tx.get(
    `
      INSERT INTO academic_v2_program_stage_templates
        (program_id, stage_number, created_at, updated_at)
      VALUES (?, ?, NOW(), NOW())
      RETURNING *
    `,
    [normalizedProgramId, normalizedStageNumber]
  );
  return row;
}

async function getProgramStageTemplateBundle(tx, programId, stageNumber) {
  const normalizedProgramId = normalizePositiveInt(programId);
  const normalizedStageNumber = normalizeCourseStageNumber(stageNumber, 1);
  const stageTemplate = await tx.get(
    `
      SELECT *
      FROM academic_v2_program_stage_templates
      WHERE program_id = ?
        AND stage_number = ?
      LIMIT 1
    `,
    [normalizedProgramId, normalizedStageNumber]
  );
  if (!stageTemplate) {
    return {
      stageTemplate: null,
      termTemplates: [],
      subjectTemplates: [],
      subjectActivities: [],
    };
  }
  const termTemplates = await tx.all(
    `
      SELECT *
      FROM academic_v2_program_stage_term_templates
      WHERE stage_template_id = ?
      ORDER BY COALESCE(sort_order, 0) ASC, term_number ASC, id ASC
    `,
    [stageTemplate.id]
  );
  const subjectTemplates = await tx.all(
    `
      SELECT
        stage_subject.*,
        subject_template.name AS subject_template_name,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT stage_term.id), NULL),
          ARRAY[]::int[]
        ) AS stage_term_template_ids,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT teacher_link.user_id), NULL),
          ARRAY[]::int[]
        ) AS teacher_ids,
        COALESCE(
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT activity.activity_type), NULL),
          ARRAY[]::text[]
        ) AS activity_types
      FROM academic_v2_program_stage_subject_templates stage_subject
      JOIN academic_v2_subject_templates subject_template ON subject_template.id = stage_subject.subject_template_id
      LEFT JOIN academic_v2_program_stage_subject_terms stage_subject_term
        ON stage_subject_term.stage_subject_template_id = stage_subject.id
      LEFT JOIN academic_v2_program_stage_term_templates stage_term
        ON stage_term.id = stage_subject_term.stage_term_template_id
      LEFT JOIN academic_v2_program_stage_subject_teachers teacher_link
        ON teacher_link.stage_subject_template_id = stage_subject.id
      LEFT JOIN academic_v2_program_stage_subject_activities activity
        ON activity.stage_subject_template_id = stage_subject.id
      WHERE stage_subject.stage_template_id = ?
      GROUP BY stage_subject.id, subject_template.name
      ORDER BY stage_subject.sort_order ASC, COALESCE(NULLIF(stage_subject.title, ''), subject_template.name) ASC, stage_subject.id ASC
    `,
    [stageTemplate.id]
  );
  const subjectActivities = await tx.all(
    `
      SELECT *
      FROM academic_v2_program_stage_subject_activities
      WHERE stage_subject_template_id IN (
        SELECT id
        FROM academic_v2_program_stage_subject_templates
        WHERE stage_template_id = ?
      )
      ORDER BY sort_order ASC, id ASC
    `,
    [stageTemplate.id]
  );
  return {
    stageTemplate,
    termTemplates: (termTemplates || []).map((item) => ({
      ...item,
      id: Number(item.id || 0),
      stage_template_id: Number(item.stage_template_id || 0),
      term_number: Number(item.term_number || 0) || 1,
      weeks_count: normalizeWeeksCount(item.weeks_count, 16),
      sort_order: normalizeSortOrder(item.sort_order, 0),
      is_active_default: item.is_active_default === true || Number(item.is_active_default) === 1,
    })),
    subjectTemplates: (subjectTemplates || []).map((item) => ({
      ...item,
      id: Number(item.id || 0),
      stage_template_id: Number(item.stage_template_id || 0),
      subject_template_id: Number(item.subject_template_id || 0),
      group_count: Math.max(1, Number(item.group_count || 0) || 1),
      default_group: Math.max(1, Number(item.default_group || 0) || 1),
      sort_order: normalizeSortOrder(item.sort_order, 0),
      is_visible: item.is_visible === true || Number(item.is_visible) === 1,
      is_required: item.is_required === true || Number(item.is_required) === 1,
      is_general: item.is_general === true || Number(item.is_general) === 1,
      show_in_teamwork: item.show_in_teamwork === true || Number(item.show_in_teamwork) === 1,
      stage_term_template_ids: normalizeIdArray(item.stage_term_template_ids || []),
      teacher_ids: normalizeIdArray(item.teacher_ids || []),
      activity_types: Array.from(new Set(
        (Array.isArray(item.activity_types) ? item.activity_types : [])
          .map((activityType) => normalizeActivityType(activityType, 'lecture'))
          .filter(Boolean)
      )).sort((a, b) => Number(ACTIVITY_ORDER[a] || 999) - Number(ACTIVITY_ORDER[b] || 999)),
    })),
    subjectActivities: (subjectActivities || []).map((item) => ({
      ...item,
      id: Number(item.id || 0),
      stage_subject_template_id: Number(item.stage_subject_template_id || 0),
      activity_type: normalizeActivityType(item.activity_type, 'lecture'),
      sort_order: normalizeSortOrder(item.sort_order, ACTIVITY_ORDER[normalizeActivityType(item.activity_type, 'lecture')] || 0),
    })),
  };
}

async function clearGroupScheduleProjection(tx, groupId) {
  const scheduleRows = await tx.all(
    `
      SELECT se.id
      FROM academic_v2_schedule_entries se
      JOIN academic_v2_group_subject_activities activity ON activity.id = se.group_subject_activity_id
      JOIN academic_v2_group_subjects gs ON gs.id = activity.group_subject_id
      WHERE gs.group_id = ?
    `,
    [groupId]
  );
  for (const scheduleRow of scheduleRows || []) {
    await deleteLegacyScheduleProjectionForEntryTx(tx, scheduleRow.id);
    await tx.run('DELETE FROM academic_v2_schedule_entries WHERE id = ?', [scheduleRow.id]);
  }
}

function buildPromotedCourseLabel(cohort, sourceGroup, targetStageNumber) {
  const campusKey = normalizeCampusKey(sourceGroup && sourceGroup.campus_key, 'kyiv');
  const campusLabel = campusKey === 'munich' ? 'Munich' : 'Kyiv';
  const cohortLabel = cleanText(cohort && cohort.label, 120) || `Cohort ${Number(cohort && cohort.admission_year || new Date().getUTCFullYear())}`;
  return `${cohortLabel} Stage ${normalizeCourseStageNumber(targetStageNumber, 1)} ${campusLabel}`;
}

async function applyStageTemplateToGroupTx(tx, groupId, { replaceExisting = false } = {}) {
  const group = await tx.get(
    `
      SELECT
        g.*,
        c.admission_year,
        c.label AS cohort_label,
        c.program_id,
        c.legacy_admission_id,
        p.name AS program_name
      FROM academic_v2_groups g
      JOIN academic_v2_cohorts c ON c.id = g.cohort_id
      JOIN academic_v2_programs p ON p.id = c.program_id
      WHERE g.id = ?
      LIMIT 1
    `,
    [normalizePositiveInt(groupId)]
  );
  if (!group) {
    throw new Error('GROUP_NOT_FOUND');
  }
  const bundle = await getProgramStageTemplateBundle(tx, group.program_id, group.stage_number);
  if (!bundle.stageTemplate) {
    throw new Error('STAGE_TEMPLATE_NOT_FOUND');
  }
  if (!(bundle.termTemplates || []).length) {
    throw new Error('STAGE_TEMPLATE_TERMS_REQUIRED');
  }
  if (!(bundle.subjectTemplates || []).length) {
    throw new Error('STAGE_TEMPLATE_SUBJECTS_REQUIRED');
  }
  if (replaceExisting) {
    await clearGroupScheduleProjection(tx, group.id);
  }

  const existingTerms = await tx.all(
    `
      SELECT *
      FROM academic_v2_terms
      WHERE group_id = ?
      ORDER BY term_number ASC, id ASC
    `,
    [group.id]
  );
  const existingTermsByNumber = new Map((existingTerms || []).map((item) => [Number(item.term_number || 0), item]));
  const activeTemplateTermIds = new Set(
    (bundle.termTemplates || [])
      .filter((item) => item.is_active_default)
      .map((item) => Number(item.id || 0))
  );
  if (!activeTemplateTermIds.size && bundle.termTemplates[0]) {
    activeTemplateTermIds.add(Number(bundle.termTemplates[0].id || 0));
  }
  const seededTermsByTemplateId = new Map();
  const seededTermsByNumber = new Map();
  for (const termTemplate of bundle.termTemplates || []) {
    const existingTerm = existingTermsByNumber.get(Number(termTemplate.term_number || 0)) || null;
    const termPayload = [
      group.id,
      Number(termTemplate.term_number || 1),
      cleanText(termTemplate.title, 120) || `Term ${Number(termTemplate.term_number || 1)}`,
      normalizeDateString(termTemplate.start_date, null),
      normalizeWeeksCount(termTemplate.weeks_count, 16),
      activeTemplateTermIds.has(Number(termTemplate.id || 0)),
    ];
    let seededTerm = null;
    if (existingTerm) {
      seededTerm = await tx.get(
        `
          UPDATE academic_v2_terms
          SET
            group_id = ?,
            term_number = ?,
            title = ?,
            start_date = ?,
            weeks_count = ?,
            is_active = ?,
            is_archived = FALSE,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [...termPayload, existingTerm.id]
      );
    } else {
      seededTerm = await tx.get(
        `
          INSERT INTO academic_v2_terms
            (group_id, term_number, title, start_date, weeks_count, is_active, is_archived, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, FALSE, NOW(), NOW())
          RETURNING *
        `,
        termPayload
      );
    }
    seededTermsByTemplateId.set(Number(termTemplate.id || 0), seededTerm);
    seededTermsByNumber.set(Number(termTemplate.term_number || 0), seededTerm);
  }
  const primaryActiveTerm = Array.from(seededTermsByTemplateId.values()).find((item) => item && (item.is_active === true || Number(item.is_active) === 1))
    || Array.from(seededTermsByTemplateId.values())[0]
    || null;
  if (primaryActiveTerm) {
    await tx.run(
      `
        UPDATE academic_v2_terms
        SET is_active = CASE WHEN id = ? THEN TRUE ELSE FALSE END,
            updated_at = NOW()
        WHERE group_id = ?
      `,
      [primaryActiveTerm.id, group.id]
    );
  }
  if (replaceExisting) {
    const templateTermNumbers = new Set((bundle.termTemplates || []).map((item) => Number(item.term_number || 0)));
    for (const existingTerm of existingTerms || []) {
      if (templateTermNumbers.has(Number(existingTerm.term_number || 0))) {
        continue;
      }
      await tx.run(
        `
          UPDATE academic_v2_terms
          SET is_active = FALSE,
              is_archived = TRUE,
              updated_at = NOW()
          WHERE id = ?
        `,
        [existingTerm.id]
      );
    }
  }

  const existingSubjects = await tx.all(
    `
      SELECT id, subject_template_id, legacy_subject_id
      FROM academic_v2_group_subjects
      WHERE group_id = ?
      ORDER BY sort_order ASC, id ASC
    `,
    [group.id]
  );
  const existingSubjectsByTemplateId = new Map((existingSubjects || []).map((item) => [Number(item.subject_template_id || 0), item]));
  const subjectActivitiesByStageSubjectId = new Map();
  for (const activity of bundle.subjectActivities || []) {
    const stageSubjectTemplateId = Number(activity.stage_subject_template_id || 0);
    if (!subjectActivitiesByStageSubjectId.has(stageSubjectTemplateId)) {
      subjectActivitiesByStageSubjectId.set(stageSubjectTemplateId, []);
    }
    subjectActivitiesByStageSubjectId.get(stageSubjectTemplateId).push({
      ...activity,
      activity_type: normalizeActivityType(activity.activity_type, 'lecture'),
      sort_order: normalizeSortOrder(activity.sort_order, ACTIVITY_ORDER[normalizeActivityType(activity.activity_type, 'lecture')] || 0),
    });
  }
  const templateSubjectIds = new Set();
  for (const stageSubject of bundle.subjectTemplates || []) {
    templateSubjectIds.add(Number(stageSubject.subject_template_id || 0));
    const existingSubject = existingSubjectsByTemplateId.get(Number(stageSubject.subject_template_id || 0)) || null;
    const title = cleanText(stageSubject.title || stageSubject.subject_template_name, 160);
    let seededSubject = null;
    if (existingSubject) {
      seededSubject = await tx.get(
        `
          UPDATE academic_v2_group_subjects
          SET
            group_id = ?,
            subject_template_id = ?,
            title = ?,
            group_count = ?,
            default_group = ?,
            is_visible = ?,
            is_required = ?,
            is_general = ?,
            show_in_teamwork = ?,
            sort_order = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [
          group.id,
          Number(stageSubject.subject_template_id || 0),
          title,
          Math.max(1, Number(stageSubject.group_count || 0) || 1),
          Math.max(1, Number(stageSubject.default_group || 0) || 1),
          Boolean(stageSubject.is_visible),
          Boolean(stageSubject.is_required),
          Boolean(stageSubject.is_general),
          Boolean(stageSubject.show_in_teamwork),
          normalizeSortOrder(stageSubject.sort_order, 0),
          existingSubject.id,
        ]
      );
    } else {
      seededSubject = await tx.get(
        `
          INSERT INTO academic_v2_group_subjects
            (group_id, subject_template_id, title, group_count, default_group, is_visible, is_required, is_general, show_in_teamwork, sort_order, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [
          group.id,
          Number(stageSubject.subject_template_id || 0),
          title,
          Math.max(1, Number(stageSubject.group_count || 0) || 1),
          Math.max(1, Number(stageSubject.default_group || 0) || 1),
          Boolean(stageSubject.is_visible),
          Boolean(stageSubject.is_required),
          Boolean(stageSubject.is_general),
          Boolean(stageSubject.show_in_teamwork),
          normalizeSortOrder(stageSubject.sort_order, 0),
        ]
      );
    }
    const seededTermIds = (
      (stageSubject.stage_term_template_ids || []).length
        ? stageSubject.stage_term_template_ids
          .map((stageTermTemplateId) => seededTermsByTemplateId.get(Number(stageTermTemplateId || 0)))
          .filter(Boolean)
        : Array.from(seededTermsByTemplateId.values())
    ).map((item) => Number(item.id || 0));
    await tx.run('DELETE FROM academic_v2_group_subject_terms WHERE group_subject_id = ?', [seededSubject.id]);
    for (const termId of normalizeIdArray(seededTermIds)) {
      await tx.run(
        `
          INSERT INTO academic_v2_group_subject_terms (group_subject_id, term_id, created_at)
          VALUES (?, ?, NOW())
          ON CONFLICT (group_subject_id, term_id) DO NOTHING
        `,
        [seededSubject.id, termId]
      );
    }
    if (replaceExisting || (stageSubject.teacher_ids || []).length) {
      await tx.run('DELETE FROM academic_v2_teacher_assignments WHERE group_subject_id = ?', [seededSubject.id]);
      for (let index = 0; index < (stageSubject.teacher_ids || []).length; index += 1) {
        await tx.run(
          `
            INSERT INTO academic_v2_teacher_assignments
              (group_subject_id, user_id, is_primary, created_at, updated_at)
            VALUES (?, ?, ?, NOW(), NOW())
          `,
          [seededSubject.id, stageSubject.teacher_ids[index], index === 0]
        );
      }
    }

    const existingActivities = await tx.all(
      `
        SELECT id, activity_type
        FROM academic_v2_group_subject_activities
        WHERE group_subject_id = ?
        ORDER BY sort_order ASC, id ASC
      `,
      [seededSubject.id]
    );
    const existingActivitiesByType = new Map(
      (existingActivities || []).map((item) => [normalizeActivityType(item.activity_type, 'lecture'), item])
    );
    const templateActivities = (subjectActivitiesByStageSubjectId.get(Number(stageSubject.id || 0)) || [])
      .slice()
      .sort((a, b) => Number(a.sort_order || 0) - Number(b.sort_order || 0));
    const seededActivityTypes = new Set();

    for (const templateActivity of templateActivities) {
      const activityType = normalizeActivityType(templateActivity.activity_type, 'lecture');
      seededActivityTypes.add(activityType);
      const sortOrder = normalizeSortOrder(templateActivity.sort_order, ACTIVITY_ORDER[activityType] || 0);
      const existingActivity = existingActivitiesByType.get(activityType) || null;
      if (existingActivity) {
        await tx.run(
          `
            UPDATE academic_v2_group_subject_activities
            SET
              activity_type = ?,
              sort_order = ?,
              updated_at = NOW()
            WHERE id = ?
          `,
          [activityType, sortOrder, existingActivity.id]
        );
      } else {
        await tx.run(
          `
            INSERT INTO academic_v2_group_subject_activities
              (group_subject_id, activity_type, sort_order, created_at, updated_at)
            VALUES (?, ?, ?, NOW(), NOW())
          `,
          [seededSubject.id, activityType, sortOrder]
        );
      }
    }
    if (!templateActivities.length) {
      seededActivityTypes.add('lecture');
    }
    await ensureGroupSubjectBaselineActivityTx(tx, seededSubject.id);

    if (replaceExisting) {
      for (const existingActivity of existingActivities || []) {
        const activityType = normalizeActivityType(existingActivity.activity_type, 'lecture');
        if (seededActivityTypes.has(activityType)) {
          continue;
        }
        await deleteScheduleRowsForActivityTx(tx, existingActivity.id);
        await tx.run('DELETE FROM academic_v2_group_subject_activities WHERE id = ?', [existingActivity.id]);
      }
    }
  }
  if (replaceExisting) {
    for (const existingSubject of existingSubjects || []) {
      if (templateSubjectIds.has(Number(existingSubject.subject_template_id || 0))) {
        continue;
      }
      await deleteScheduleRowsForGroupSubjectTx(tx, existingSubject.id);
      await hideLegacySubject(tx, group.legacy_admission_id, existingSubject.legacy_subject_id);
      await tx.run('DELETE FROM academic_v2_group_subjects WHERE id = ?', [existingSubject.id]);
    }
  }

  return {
    groupId: Number(group.id || 0),
    programId: Number(group.program_id || 0),
    stageNumber: normalizeCourseStageNumber(group.stage_number, 1),
    termTemplateCount: (bundle.termTemplates || []).length,
    subjectTemplateCount: (bundle.subjectTemplates || []).length,
  };
}

async function ensurePromotionTargetCourseTx(tx, cohort, sourceGroup, targetStageNumber) {
  const existingTargetCourse = await tx.get(
    `
      SELECT *
      FROM academic_v2_groups
      WHERE cohort_id = ?
        AND stage_number = ?
        AND campus_key = ?
      ORDER BY is_active DESC, id ASC
      LIMIT 1
    `,
    [
      Number(cohort.id || 0),
      normalizeCourseStageNumber(targetStageNumber, 1),
      normalizeCampusKey(sourceGroup.campus_key, 'kyiv'),
    ]
  );
  if (existingTargetCourse) {
    await tx.run(
      `
        UPDATE academic_v2_groups
        SET is_active = TRUE,
            updated_at = NOW()
        WHERE id = ?
      `,
      [existingTargetCourse.id]
    );
    return {
      ...existingTargetCourse,
      id: Number(existingTargetCourse.id || 0),
    };
  }
  const inserted = await tx.get(
    `
      INSERT INTO academic_v2_groups
        (cohort_id, stage_number, campus_key, code, label, is_active, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, TRUE, NOW(), NOW())
      RETURNING *
    `,
    [
      Number(cohort.id || 0),
      normalizeCourseStageNumber(targetStageNumber, 1),
      normalizeCampusKey(sourceGroup.campus_key, 'kyiv'),
      cleanText(sourceGroup.code, 40) || null,
      buildPromotedCourseLabel(cohort, sourceGroup, targetStageNumber),
    ]
  );
  return inserted;
}

async function archiveLegacySemester(tx, legacySemesterId) {
  const normalizedSemesterId = normalizePositiveInt(legacySemesterId);
  if (!normalizedSemesterId) return;
  await tx.run(
    `
      UPDATE semesters
      SET is_active = 0,
          is_archived = 1
      WHERE id = ?
    `,
    [normalizedSemesterId]
  );
}

async function hideLegacySubject(tx, legacyAdmissionId, legacySubjectId) {
  const normalizedAdmissionId = normalizePositiveInt(legacyAdmissionId);
  const normalizedSubjectId = normalizePositiveInt(legacySubjectId);
  if (!normalizedSubjectId) return;
  await tx.run('UPDATE subjects SET visible = 0 WHERE id = ?', [normalizedSubjectId]);
  if (normalizedAdmissionId) {
    await tx.run(
      `
        INSERT INTO subject_visibility_by_admission
          (admission_id, subject_id, is_visible, created_at, updated_at)
        VALUES (?, ?, FALSE, NOW(), NOW())
        ON CONFLICT (admission_id, subject_id)
        DO UPDATE SET
          is_visible = FALSE,
          updated_at = NOW()
      `,
      [normalizedAdmissionId, normalizedSubjectId]
    );
  }
}

async function deleteProgram(store, programId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT id, legacy_program_id
        FROM academic_v2_programs
        WHERE id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(programId)]
    );
    if (!row) {
      throw new Error('PROGRAM_NOT_FOUND');
    }
    const legacyProgramId = normalizePositiveInt(row.legacy_program_id);
    const dependencyRow = await tx.get(
      `
        SELECT
          (SELECT COUNT(*)::int FROM academic_v2_cohorts WHERE program_id = ?) AS cohort_count,
          (SELECT COUNT(*)::int FROM academic_v2_program_stage_templates WHERE program_id = ?) AS stage_template_count,
          (SELECT COUNT(*)::int FROM program_admissions WHERE program_id = ?) AS legacy_admission_count,
          (SELECT COUNT(*)::int FROM users WHERE study_program_id = ?) AS user_count
      `,
      [row.id, row.id, legacyProgramId, legacyProgramId]
    );
    if (
      Number(dependencyRow?.cohort_count || 0) > 0
      || Number(dependencyRow?.stage_template_count || 0) > 0
      || Number(dependencyRow?.legacy_admission_count || 0) > 0
      || Number(dependencyRow?.user_count || 0) > 0
    ) {
      throw new Error('PROGRAM_DELETE_BLOCKED');
    }
    if (legacyProgramId) {
      await tx.run('DELETE FROM study_programs WHERE id = ?', [legacyProgramId]);
    }
    await tx.run('DELETE FROM academic_v2_programs WHERE id = ?', [row.id]);
    return { row };
  });
}

async function deleteCohort(store, cohortId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT id, program_id, legacy_admission_id
        FROM academic_v2_cohorts
        WHERE id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(cohortId)]
    );
    if (!row) {
      throw new Error('COHORT_NOT_FOUND');
    }
    const legacyAdmissionId = normalizePositiveInt(row.legacy_admission_id);
    const dependencyRow = await tx.get(
      `
        SELECT
          (SELECT COUNT(*)::int FROM academic_v2_groups WHERE cohort_id = ?) AS group_count,
          (SELECT COUNT(*)::int FROM program_admission_courses WHERE admission_id = ?) AS legacy_course_mapping_count,
          (SELECT COUNT(*)::int FROM subject_visibility_by_admission WHERE admission_id = ?) AS legacy_subject_visibility_count,
          (SELECT COUNT(*)::int FROM users WHERE admission_id = ?) AS user_count
      `,
      [row.id, legacyAdmissionId, legacyAdmissionId, legacyAdmissionId]
    );
    if (
      Number(dependencyRow?.group_count || 0) > 0
      || Number(dependencyRow?.legacy_course_mapping_count || 0) > 0
      || Number(dependencyRow?.legacy_subject_visibility_count || 0) > 0
      || Number(dependencyRow?.user_count || 0) > 0
    ) {
      throw new Error('COHORT_DELETE_BLOCKED');
    }
    if (legacyAdmissionId) {
      await tx.run('DELETE FROM program_admissions WHERE id = ?', [legacyAdmissionId]);
    }
    await tx.run('DELETE FROM academic_v2_cohorts WHERE id = ?', [row.id]);
    return { row };
  });
}

async function deleteGroup(store, groupId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT
          g.id,
          g.cohort_id,
          g.legacy_course_id,
          g.legacy_study_context_id,
          c.program_id
        FROM academic_v2_groups g
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        WHERE g.id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(groupId)]
    );
    if (!row) {
      throw new Error('GROUP_NOT_FOUND');
    }
    const legacyCourseId = normalizePositiveInt(row.legacy_course_id);
    const legacyStudyContextId = normalizePositiveInt(row.legacy_study_context_id);
    const dependencyRow = await tx.get(
      `
        SELECT
          (SELECT COUNT(*)::int FROM academic_v2_terms WHERE group_id = ?) AS term_count,
          (SELECT COUNT(*)::int FROM academic_v2_group_subjects WHERE group_id = ?) AS group_subject_count,
          (SELECT COUNT(*)::int FROM academic_v2_student_enrollments WHERE group_id = ?) AS enrollment_count,
          (SELECT COUNT(*)::int FROM users WHERE group_id = ?) AS direct_user_count,
          (SELECT COUNT(*)::int FROM semesters WHERE course_id = ?) AS legacy_semester_count,
          (SELECT COUNT(*)::int FROM subjects WHERE course_id = ?) AS legacy_subject_count,
          (SELECT COUNT(*)::int FROM schedule_entries WHERE course_id = ?) AS legacy_schedule_count,
          (SELECT COUNT(*)::int FROM users WHERE course_id = ?) AS legacy_course_user_count
      `,
      [row.id, row.id, row.id, row.id, legacyCourseId, legacyCourseId, legacyCourseId, legacyCourseId]
    );
    if (
      legacyStudyContextId
      || Number(dependencyRow?.term_count || 0) > 0
      || Number(dependencyRow?.group_subject_count || 0) > 0
      || Number(dependencyRow?.enrollment_count || 0) > 0
      || Number(dependencyRow?.direct_user_count || 0) > 0
      || Number(dependencyRow?.legacy_semester_count || 0) > 0
      || Number(dependencyRow?.legacy_subject_count || 0) > 0
      || Number(dependencyRow?.legacy_schedule_count || 0) > 0
      || Number(dependencyRow?.legacy_course_user_count || 0) > 0
    ) {
      throw new Error('GROUP_DELETE_BLOCKED');
    }
    if (legacyCourseId) {
      await tx.run('DELETE FROM courses WHERE id = ?', [legacyCourseId]);
    }
    await tx.run('DELETE FROM academic_v2_groups WHERE id = ?', [row.id]);
    return { row };
  });
}

async function deleteSubjectTemplate(store, templateId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT id, legacy_catalog_id
        FROM academic_v2_subject_templates
        WHERE id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(templateId)]
    );
    if (!row) {
      throw new Error('SUBJECT_TEMPLATE_NOT_FOUND');
    }
    const legacyCatalogId = normalizePositiveInt(row.legacy_catalog_id);
    const dependencyRow = await tx.get(
      `
        SELECT
          (SELECT COUNT(*)::int FROM academic_v2_group_subjects WHERE subject_template_id = ?) AS group_subject_count,
          (SELECT COUNT(*)::int FROM academic_v2_program_stage_subject_templates WHERE subject_template_id = ?) AS stage_subject_template_count,
          (SELECT COUNT(*)::int FROM subjects WHERE catalog_id = ?) AS legacy_subject_count,
          (SELECT COUNT(*)::int FROM program_preset_stage_subjects WHERE subject_catalog_id = ?) AS preset_subject_count,
          (SELECT COUNT(*)::int FROM subject_offerings WHERE subject_catalog_id = ?) AS legacy_offering_count,
          (SELECT COUNT(*)::int FROM teacher_assignment_templates WHERE subject_catalog_id = ?) AS teacher_template_count
      `,
      [row.id, row.id, legacyCatalogId, legacyCatalogId, legacyCatalogId, legacyCatalogId]
    );
    if (
      Number(dependencyRow?.group_subject_count || 0) > 0
      || Number(dependencyRow?.stage_subject_template_count || 0) > 0
      || Number(dependencyRow?.legacy_subject_count || 0) > 0
      || Number(dependencyRow?.preset_subject_count || 0) > 0
      || Number(dependencyRow?.legacy_offering_count || 0) > 0
      || Number(dependencyRow?.teacher_template_count || 0) > 0
    ) {
      throw new Error('SUBJECT_TEMPLATE_DELETE_BLOCKED');
    }
    if (legacyCatalogId) {
      await tx.run('DELETE FROM subject_catalog WHERE id = ?', [legacyCatalogId]);
    }
    await tx.run('DELETE FROM academic_v2_subject_templates WHERE id = ?', [row.id]);
    return { row };
  });
}

async function saveProgram(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
    const programId = normalizePositiveInt(payload.program_id || payload.id);
    const name = cleanText(payload.name, 160);
    if (!name) {
      throw new Error('PROGRAM_NAME_REQUIRED');
    }
    const trackKey = normalizeTrackKey(payload.track_key || payload.track, 'bachelor');
    const sortOrder = normalizeSortOrder(payload.sort_order, 100);
    let row;
    if (programId) {
      row = await tx.get(
        `
          UPDATE academic_v2_programs
          SET
            track_key = ?,
            code = ?,
            name = ?,
            sort_order = ?,
            is_active = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [trackKey, cleanText(payload.code, 40) || null, name, sortOrder, normalizeBoolean(payload.is_active, true), programId]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_programs
            (track_key, code, name, sort_order, is_active, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [trackKey, cleanText(payload.code, 40) || null, name, sortOrder, normalizeBoolean(payload.is_active, true)]
      );
    }
    await ensureLegacyProgram(tx, Number(row.id));
    return { row };
  });
}

async function saveCohort(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
    const cohortId = normalizePositiveInt(payload.cohort_id || payload.id);
    const programId = normalizePositiveInt(payload.program_id);
    const admissionYear = normalizePositiveInt(payload.admission_year, new Date().getUTCFullYear());
    const currentStageNumber = payload.current_stage_number == null
      ? null
      : normalizeCourseStageNumber(payload.current_stage_number, 1);
    if (!programId) {
      throw new Error('PROGRAM_REQUIRED');
    }
    let row;
    if (cohortId) {
      row = await tx.get(
        `
          UPDATE academic_v2_cohorts
          SET
            program_id = ?,
            admission_year = ?,
            label = ?,
            ${currentStageNumber == null ? '' : 'current_stage_number = ?,\n            '}
            is_active = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [
          programId,
          admissionYear,
          cleanText(payload.label, 120) || `Cohort ${admissionYear}`,
          ...(currentStageNumber == null ? [] : [currentStageNumber]),
          normalizeBoolean(payload.is_active, true),
          cohortId,
        ]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_cohorts
            (program_id, admission_year, label, current_stage_number, is_active, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [
          programId,
          admissionYear,
          cleanText(payload.label, 120) || `Cohort ${admissionYear}`,
          normalizeCourseStageNumber(currentStageNumber, 1),
          normalizeBoolean(payload.is_active, true),
        ]
      );
    }
    await ensureLegacyAdmission(tx, Number(row.id));
    return { row };
  });
}

async function saveGroup(store, payload = {}) {
  const result = await withStoreTransaction(store, async (tx) => {
    try {
      const groupId = normalizePositiveInt(payload.group_id || payload.id);
      const cohortId = normalizePositiveInt(payload.cohort_id);
      if (!cohortId) {
        throw new Error('COHORT_REQUIRED');
      }
      const cohort = await tx.get(
        `
          SELECT c.id, c.program_id, p.track_key
          FROM academic_v2_cohorts c
          JOIN academic_v2_programs p ON p.id = c.program_id
          WHERE c.id = ?
          LIMIT 1
        `,
        [cohortId]
      );
      if (!cohort) {
        throw new Error('COHORT_NOT_FOUND');
      }
      const label = cleanText(payload.label, 160);
      if (!label) {
        throw new Error('GROUP_LABEL_REQUIRED');
      }
      const stageNumber = normalizeCourseStageNumber(payload.stage_number, 1);
      const campusKey = normalizeCampusKey(payload.campus_key, 'kyiv');
      const isTeacherTrack = normalizeTrackKey(cohort.track_key, 'bachelor') === 'teacher';
      const isTeacherRegistrationDefault = isTeacherTrack
        ? normalizeBoolean(payload.is_teacher_registration_default, false)
        : false;
      if (groupId) {
        const existingGroup = await tx.get(
          `
            SELECT id
            FROM academic_v2_groups
            WHERE id = ?
            LIMIT 1
          `,
          [groupId]
        );
        if (!existingGroup) {
          throw new Error('GROUP_NOT_FOUND');
        }
      }
      await assertUniqueStageCampusCourse(tx, {
        groupId,
        cohortId,
        stageNumber,
        campusKey,
      });
      let row;
      if (groupId) {
        row = await tx.get(
          `
            UPDATE academic_v2_groups
            SET
              cohort_id = ?,
              stage_number = ?,
              campus_key = ?,
              code = ?,
              label = ?,
              is_teacher_registration_default = ?,
              is_active = ?,
              updated_at = NOW()
            WHERE id = ?
            RETURNING *
          `,
          [
            cohortId,
            stageNumber,
            campusKey,
            cleanText(payload.code, 40) || null,
            label,
            isTeacherRegistrationDefault,
            normalizeBoolean(payload.is_active, true),
            groupId,
          ]
        );
      } else {
        row = await tx.get(
          `
            INSERT INTO academic_v2_groups
              (cohort_id, stage_number, campus_key, code, label, is_teacher_registration_default, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
            RETURNING *
          `,
          [
            cohortId,
            stageNumber,
            campusKey,
            cleanText(payload.code, 40) || null,
            label,
            isTeacherRegistrationDefault,
            normalizeBoolean(payload.is_active, true),
          ]
        );
      }
      if (!row) {
        throw new Error(groupId ? 'GROUP_NOT_FOUND' : 'COHORT_NOT_FOUND');
      }
      if (isTeacherTrack && isTeacherRegistrationDefault) {
        await tx.run(
          `
            UPDATE academic_v2_groups AS other_group
            SET
              is_teacher_registration_default = FALSE,
              updated_at = NOW()
            FROM academic_v2_cohorts AS other_cohort
            WHERE other_group.cohort_id = other_cohort.id
              AND other_cohort.program_id = ?
              AND LOWER(COALESCE(NULLIF(TRIM(other_group.campus_key), ''), 'kyiv')) = ?
              AND other_group.id <> ?
              AND COALESCE(other_group.is_teacher_registration_default, FALSE) = TRUE
          `,
          [
            Number(cohort.program_id || 0),
            normalizeCampusKey(campusKey, 'kyiv'),
            Number(row.id || 0),
          ]
        );
      }
      const enrichedRow = await tx.get(
        `
          SELECT g.*, c.program_id, p.track_key
          FROM academic_v2_groups g
          JOIN academic_v2_cohorts c ON c.id = g.cohort_id
          JOIN academic_v2_programs p ON p.id = c.program_id
          WHERE g.id = ?
          LIMIT 1
        `,
        [Number(row.id || 0)]
      );
      return {
        row: enrichedRow || {
          ...row,
          program_id: Number(cohort.program_id || 0),
        },
      };
    } catch (err) {
      const normalizedErrorKey = normalizeAcademicV2GroupSaveErrorKey(err);
      if (normalizedErrorKey) {
        throw normalizedErrorKey === String(err?.message || '').trim()
          ? err
          : new Error(normalizedErrorKey);
      }
      throw err;
    }
  });
  return {
    ...result,
    ...(await runProjectionSyncSafely(store, result && result.row && result.row.id, 'academicV2.saveGroup')),
  };
}

async function saveTerm(store, payload = {}) {
  const result = await withStoreTransaction(store, async (tx) => {
    const termId = normalizePositiveInt(payload.term_id || payload.id);
    const groupId = normalizePositiveInt(payload.group_id);
    if (!groupId) {
      throw new Error('GROUP_REQUIRED');
    }
    const title = cleanText(payload.title, 120) || `Term ${normalizeStageNumber(payload.term_number, 1)}`;
    const termNumber = normalizeStageNumber(payload.term_number, 1);
    const isActive = normalizeBoolean(payload.is_active, false);
    let row;
    if (termId) {
      row = await tx.get(
        `
          UPDATE academic_v2_terms
          SET
            group_id = ?,
            term_number = ?,
            title = ?,
            start_date = ?,
            weeks_count = ?,
            is_active = ?,
            is_archived = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [
          groupId,
          termNumber,
          title,
          normalizeDateString(payload.start_date, new Date().toISOString().slice(0, 10)),
          normalizeWeeksCount(payload.weeks_count, 16),
          isActive,
          normalizeBoolean(payload.is_archived, false),
          termId,
        ]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_terms
            (group_id, term_number, title, start_date, weeks_count, is_active, is_archived, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [
          groupId,
          termNumber,
          title,
          normalizeDateString(payload.start_date, new Date().toISOString().slice(0, 10)),
          normalizeWeeksCount(payload.weeks_count, 16),
          isActive,
          normalizeBoolean(payload.is_archived, false),
        ]
      );
    }
    if (isActive) {
      await tx.run(
        `
          UPDATE academic_v2_terms
          SET is_active = CASE WHEN id = ? THEN TRUE ELSE FALSE END,
              updated_at = NOW()
          WHERE group_id = ?
        `,
        [row.id, groupId]
      );
    }
    return { row };
  });
  return {
    ...result,
    ...(await runProjectionSyncSafely(store, result && result.row && result.row.group_id, 'academicV2.saveTerm')),
  };
}

async function deleteTerm(store, termId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT id, group_id, legacy_semester_id
        FROM academic_v2_terms
        WHERE id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(termId)]
    );
    if (!row) {
      throw new Error('TERM_NOT_FOUND');
    }
    await deleteScheduleRowsForTermTx(tx, row.id);
    await archiveLegacySemester(tx, row.legacy_semester_id);
    await tx.run('DELETE FROM academic_v2_terms WHERE id = ?', [row.id]);
    return { row };
  });
}

async function saveSubjectTemplate(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
    const templateId = normalizePositiveInt(payload.subject_template_id || payload.id);
    const name = cleanText(payload.name, 160);
    if (!name) {
      throw new Error('TEMPLATE_NAME_REQUIRED');
    }
    const normalizedName = normalizeSubjectTemplateName(name);
    let row;
    if (templateId) {
      row = await tx.get(
        `
          UPDATE academic_v2_subject_templates
          SET
            name = ?,
            normalized_name = ?,
            is_active = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [name, normalizedName, normalizeBoolean(payload.is_active, true), templateId]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_subject_templates
            (name, normalized_name, is_active, created_at, updated_at)
          VALUES (?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [name, normalizedName, normalizeBoolean(payload.is_active, true)]
      );
    }
    return { row };
  });
}

async function saveProgramStageTermTemplate(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
    const stageTermTemplateId = normalizePositiveInt(payload.stage_term_template_id || payload.id);
    const programId = normalizePositiveInt(payload.program_id);
    if (!programId) {
      throw new Error('PROGRAM_REQUIRED');
    }
    const stageNumber = normalizeCourseStageNumber(payload.stage_number, 1);
    const stageTemplate = await ensureProgramStageTemplate(tx, programId, stageNumber);
    const termNumber = normalizeStageNumber(payload.term_number, 1);
    const title = cleanText(payload.title, 120) || `Term ${termNumber}`;
    const isActiveDefault = normalizeBoolean(payload.is_active_default, false);
    let row;
    if (stageTermTemplateId) {
      row = await tx.get(
        `
          UPDATE academic_v2_program_stage_term_templates
          SET
            term_number = ?,
            title = ?,
            start_date = ?,
            weeks_count = ?,
            is_active_default = ?,
            sort_order = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [
          termNumber,
          title,
          normalizeDateString(payload.start_date, null),
          normalizeWeeksCount(payload.weeks_count, 16),
          isActiveDefault,
          normalizeSortOrder(payload.sort_order, termNumber),
          stageTermTemplateId,
        ]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_program_stage_term_templates
            (stage_template_id, term_number, title, start_date, weeks_count, is_active_default, sort_order, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [
          stageTemplate.id,
          termNumber,
          title,
          normalizeDateString(payload.start_date, null),
          normalizeWeeksCount(payload.weeks_count, 16),
          isActiveDefault,
          normalizeSortOrder(payload.sort_order, termNumber),
        ]
      );
    }
    if (isActiveDefault) {
      await tx.run(
        `
          UPDATE academic_v2_program_stage_term_templates
          SET is_active_default = CASE WHEN id = ? THEN TRUE ELSE FALSE END,
              updated_at = NOW()
          WHERE stage_template_id = ?
        `,
        [row.id, stageTemplate.id]
      );
    }
    return {
      row: {
        ...row,
        program_id: programId,
        stage_number: stageNumber,
      },
    };
  });
}

async function deleteProgramStageTermTemplate(store, stageTermTemplateId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT
          term_template.*,
          stage_template.program_id,
          stage_template.stage_number
        FROM academic_v2_program_stage_term_templates term_template
        JOIN academic_v2_program_stage_templates stage_template ON stage_template.id = term_template.stage_template_id
        WHERE term_template.id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(stageTermTemplateId)]
    );
    if (!row) {
      throw new Error('STAGE_TERM_TEMPLATE_NOT_FOUND');
    }
    await tx.run('DELETE FROM academic_v2_program_stage_term_templates WHERE id = ?', [row.id]);
    return { row };
  });
}

async function saveProgramStageSubjectTemplate(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
    const stageSubjectTemplateId = normalizePositiveInt(payload.stage_subject_template_id || payload.id);
    const programId = normalizePositiveInt(payload.program_id);
    const subjectTemplateId = normalizePositiveInt(payload.subject_template_id);
    if (!programId) {
      throw new Error('PROGRAM_REQUIRED');
    }
    if (!subjectTemplateId) {
      throw new Error('SUBJECT_TEMPLATE_NOT_FOUND');
    }
    const stageNumber = normalizeCourseStageNumber(payload.stage_number, 1);
    const stageTemplate = await ensureProgramStageTemplate(tx, programId, stageNumber);
    const subjectTemplate = await tx.get(
      'SELECT id, name FROM academic_v2_subject_templates WHERE id = ? LIMIT 1',
      [subjectTemplateId]
    );
    if (!subjectTemplate) {
      throw new Error('SUBJECT_TEMPLATE_NOT_FOUND');
    }
    const title = cleanText(payload.title, 160) || cleanText(subjectTemplate.name, 160);
    let row;
    if (stageSubjectTemplateId) {
      row = await tx.get(
        `
          UPDATE academic_v2_program_stage_subject_templates
          SET
            subject_template_id = ?,
            title = ?,
            group_count = ?,
            default_group = ?,
            is_visible = ?,
            is_required = ?,
            is_general = ?,
            show_in_teamwork = ?,
            sort_order = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [
          subjectTemplateId,
          title,
          Math.max(1, Number(payload.group_count || 0) || 1),
          Math.max(1, Number(payload.default_group || 0) || 1),
          normalizeBoolean(payload.is_visible, true),
          normalizeBoolean(payload.is_required, true),
          normalizeBoolean(payload.is_general, true),
          normalizeBoolean(payload.show_in_teamwork, true),
          normalizeSortOrder(payload.sort_order, 0),
          stageSubjectTemplateId,
        ]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_program_stage_subject_templates
            (stage_template_id, subject_template_id, title, group_count, default_group, is_visible, is_required, is_general, show_in_teamwork, sort_order, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [
          stageTemplate.id,
          subjectTemplateId,
          title,
          Math.max(1, Number(payload.group_count || 0) || 1),
          Math.max(1, Number(payload.default_group || 0) || 1),
          normalizeBoolean(payload.is_visible, true),
          normalizeBoolean(payload.is_required, true),
          normalizeBoolean(payload.is_general, true),
          normalizeBoolean(payload.show_in_teamwork, true),
          normalizeSortOrder(payload.sort_order, 0),
        ]
      );
    }
    await tx.run('DELETE FROM academic_v2_program_stage_subject_terms WHERE stage_subject_template_id = ?', [row.id]);
    for (const stageTermTemplateId of normalizeIdArray(payload.stage_term_template_ids || [])) {
      await tx.run(
        `
          INSERT INTO academic_v2_program_stage_subject_terms (stage_subject_template_id, stage_term_template_id, created_at)
          VALUES (?, ?, NOW())
          ON CONFLICT (stage_subject_template_id, stage_term_template_id) DO NOTHING
        `,
        [row.id, stageTermTemplateId]
      );
    }
    await tx.run('DELETE FROM academic_v2_program_stage_subject_teachers WHERE stage_subject_template_id = ?', [row.id]);
    const teacherIds = normalizeIdArray(payload.teacher_ids || []);
    for (let index = 0; index < teacherIds.length; index += 1) {
      await tx.run(
        `
          INSERT INTO academic_v2_program_stage_subject_teachers
            (stage_subject_template_id, user_id, is_primary, created_at)
          VALUES (?, ?, ?, NOW())
        `,
        [row.id, teacherIds[index], index === 0]
      );
    }
    await ensureProgramStageSubjectBaselineActivityTx(tx, row.id);
    return {
      row: {
        ...row,
        program_id: programId,
        stage_number: stageNumber,
      },
    };
  });
}

async function deleteProgramStageSubjectTemplate(store, stageSubjectTemplateId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT
          stage_subject.*,
          stage_template.program_id,
          stage_template.stage_number
        FROM academic_v2_program_stage_subject_templates stage_subject
        JOIN academic_v2_program_stage_templates stage_template ON stage_template.id = stage_subject.stage_template_id
        WHERE stage_subject.id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(stageSubjectTemplateId)]
    );
    if (!row) {
      throw new Error('STAGE_SUBJECT_TEMPLATE_NOT_FOUND');
    }
    await tx.run('DELETE FROM academic_v2_program_stage_subject_templates WHERE id = ?', [row.id]);
    return { row };
  });
}

async function saveProgramStageSubjectActivity(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
    const activityId = normalizePositiveInt(payload.stage_subject_activity_id || payload.id);
    const stageSubjectTemplateId = normalizePositiveInt(payload.stage_subject_template_id);
    if (!stageSubjectTemplateId) {
      throw new Error('STAGE_SUBJECT_TEMPLATE_NOT_FOUND');
    }
    const stageSubjectTemplate = await tx.get(
      `
        SELECT
          stage_subject.id,
          stage_template.program_id,
          stage_template.stage_number
        FROM academic_v2_program_stage_subject_templates stage_subject
        JOIN academic_v2_program_stage_templates stage_template ON stage_template.id = stage_subject.stage_template_id
        WHERE stage_subject.id = ?
        LIMIT 1
      `,
      [stageSubjectTemplateId]
    );
    if (!stageSubjectTemplate) {
      throw new Error('STAGE_SUBJECT_TEMPLATE_NOT_FOUND');
    }
    const activityType = normalizeActivityType(payload.activity_type, 'lecture');
    const sortOrder = normalizeSortOrder(payload.sort_order, ACTIVITY_ORDER[activityType] || 0);
    const existingActivity = activityId
      ? await tx.get(
        'SELECT id FROM academic_v2_program_stage_subject_activities WHERE id = ? LIMIT 1',
        [activityId]
      )
      : null;
    if (activityId && !existingActivity) {
      throw new Error('STAGE_SUBJECT_ACTIVITY_NOT_FOUND');
    }
    const conflictingActivity = activityId
      ? await tx.get(
        `
          SELECT id
          FROM academic_v2_program_stage_subject_activities
          WHERE stage_subject_template_id = ?
            AND activity_type = ?
            AND id <> ?
          LIMIT 1
        `,
        [stageSubjectTemplateId, activityType, activityId]
      )
      : await tx.get(
        `
          SELECT id
          FROM academic_v2_program_stage_subject_activities
          WHERE stage_subject_template_id = ?
            AND activity_type = ?
          LIMIT 1
        `,
        [stageSubjectTemplateId, activityType]
      );
    if (conflictingActivity) {
      throw new Error('STAGE_SUBJECT_ACTIVITY_DUPLICATE');
    }
    let row;
    if (existingActivity) {
      row = await tx.get(
        `
          UPDATE academic_v2_program_stage_subject_activities
          SET
            stage_subject_template_id = ?,
            activity_type = ?,
            sort_order = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [stageSubjectTemplateId, activityType, sortOrder, existingActivity.id]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_program_stage_subject_activities
            (stage_subject_template_id, activity_type, sort_order, created_at, updated_at)
          VALUES (?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [stageSubjectTemplateId, activityType, sortOrder]
      );
    }
    return {
      row: {
        ...row,
        program_id: Number(stageSubjectTemplate.program_id || 0),
        stage_number: normalizeCourseStageNumber(stageSubjectTemplate.stage_number, 1),
      },
    };
  });
}

async function deleteProgramStageSubjectActivity(store, stageSubjectActivityId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT
          activity.*,
          stage_template.program_id,
          stage_template.stage_number
        FROM academic_v2_program_stage_subject_activities activity
        JOIN academic_v2_program_stage_subject_templates stage_subject ON stage_subject.id = activity.stage_subject_template_id
        JOIN academic_v2_program_stage_templates stage_template ON stage_template.id = stage_subject.stage_template_id
        WHERE activity.id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(stageSubjectActivityId)]
    );
    if (!row) {
      throw new Error('STAGE_SUBJECT_ACTIVITY_NOT_FOUND');
    }
    const remainingActivity = await tx.get(
      `
        SELECT id
        FROM academic_v2_program_stage_subject_activities
        WHERE stage_subject_template_id = ?
          AND id <> ?
        LIMIT 1
      `,
      [normalizePositiveInt(row.stage_subject_template_id), row.id]
    );
    if (!remainingActivity) {
      throw new Error('STAGE_SUBJECT_ACTIVITY_REQUIRED');
    }
    await tx.run('DELETE FROM academic_v2_program_stage_subject_activities WHERE id = ?', [row.id]);
    return { row };
  });
}

async function applyProgramStageSubjectActivityPreset(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
    const stageSubjectTemplateId = normalizePositiveInt(payload.stage_subject_template_id);
    if (!stageSubjectTemplateId) {
      throw new Error('STAGE_SUBJECT_TEMPLATE_NOT_FOUND');
    }
    const stageSubjectTemplate = await tx.get(
      `
        SELECT
          stage_subject.id,
          stage_template.program_id,
          stage_template.stage_number
        FROM academic_v2_program_stage_subject_templates stage_subject
        JOIN academic_v2_program_stage_templates stage_template ON stage_template.id = stage_subject.stage_template_id
        WHERE stage_subject.id = ?
        LIMIT 1
      `,
      [stageSubjectTemplateId]
    );
    if (!stageSubjectTemplate) {
      throw new Error('STAGE_SUBJECT_TEMPLATE_NOT_FOUND');
    }
    const activityTypes = resolveSubjectActivityPresetTypes(payload.preset_key);
    for (const activityType of activityTypes) {
      const existing = await tx.get(
        `
          SELECT id
          FROM academic_v2_program_stage_subject_activities
          WHERE stage_subject_template_id = ?
            AND activity_type = ?
          LIMIT 1
        `,
        [stageSubjectTemplateId, activityType]
      );
      if (existing) {
        continue;
      }
      await tx.run(
        `
          INSERT INTO academic_v2_program_stage_subject_activities
            (stage_subject_template_id, activity_type, sort_order, created_at, updated_at)
          VALUES (?, ?, ?, NOW(), NOW())
        `,
        [stageSubjectTemplateId, activityType, ACTIVITY_ORDER[activityType] || 0]
      );
    }
    return {
      row: {
        id: stageSubjectTemplateId,
        program_id: Number(stageSubjectTemplate.program_id || 0),
        stage_number: normalizeCourseStageNumber(stageSubjectTemplate.stage_number, 1),
      },
    };
  });
}

async function applyStageTemplateToGroup(store, groupId) {
  const result = await withStoreTransaction(store, async (tx) => {
    const seeded = await applyStageTemplateToGroupTx(tx, groupId, { replaceExisting: false });
    const row = await tx.get(
      `
        SELECT g.*, c.program_id
        FROM academic_v2_groups g
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        WHERE g.id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(groupId)]
    );
    return {
      ...seeded,
      row,
    };
  });
  return {
    ...result,
    ...(await runProjectionSyncSafely(store, result.groupId, 'academicV2.applyStageTemplateToGroup')),
  };
}

async function promoteCohortStage(store, cohortId, payload = {}) {
  const targetStageNumber = normalizeCourseStageNumber(payload.target_stage_number, 2);
  const result = await withStoreTransaction(store, async (tx) => {
    const cohort = await tx.get(
      `
        SELECT *
        FROM academic_v2_cohorts
        WHERE id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(cohortId)]
    );
    if (!cohort) {
      throw new Error('COHORT_NOT_FOUND');
    }
    const currentStageNumber = normalizeCourseStageNumber(cohort.current_stage_number, 1);
    if (targetStageNumber === currentStageNumber) {
      throw new Error('COHORT_STAGE_ALREADY_ACTIVE');
    }
    const sourceCourses = await tx.all(
      `
        SELECT *
        FROM academic_v2_groups
        WHERE cohort_id = ?
          AND stage_number = ?
          AND ${sqlTruthyExpr('is_active', true)}
        ORDER BY campus_key ASC, id ASC
      `,
      [cohort.id, currentStageNumber]
    );
    if (!(sourceCourses || []).length) {
      throw new Error('COHORT_CURRENT_STAGE_EMPTY');
    }
    const affectedGroupIds = [];
    for (const sourceCourse of sourceCourses || []) {
      const targetCourse = await ensurePromotionTargetCourseTx(tx, cohort, sourceCourse, targetStageNumber);
      affectedGroupIds.push(Number(sourceCourse.id || 0), Number(targetCourse.id || 0));
      await applyStageTemplateToGroupTx(tx, targetCourse.id, { replaceExisting: true });
      const enrollments = await tx.all(
        `
          SELECT user_id
          FROM academic_v2_student_enrollments
          WHERE group_id = ?
        `,
        [sourceCourse.id]
      );
      for (const enrollment of enrollments || []) {
        const userId = normalizePositiveInt(enrollment.user_id);
        if (!userId) continue;
        await tx.run('DELETE FROM academic_v2_student_enrollments WHERE user_id = ?', [userId]);
        await tx.run(
          `
            INSERT INTO academic_v2_student_enrollments
              (group_id, user_id, is_primary, created_at, updated_at)
            VALUES (?, ?, TRUE, NOW(), NOW())
          `,
          [targetCourse.id, userId]
        );
      }
      await tx.run(
        `
          UPDATE academic_v2_groups
          SET is_active = FALSE,
              updated_at = NOW()
          WHERE id = ?
        `,
        [sourceCourse.id]
      );
      await tx.run(
        `
          UPDATE academic_v2_terms
          SET is_active = FALSE,
              is_archived = TRUE,
              updated_at = NOW()
          WHERE group_id = ?
        `,
        [sourceCourse.id]
      );
    }
    await tx.run(
      `
        UPDATE academic_v2_cohorts
        SET current_stage_number = ?,
            updated_at = NOW()
        WHERE id = ?
      `,
      [targetStageNumber, cohort.id]
    );
    const firstTargetCourse = await tx.get(
      `
        SELECT g.*, c.program_id
        FROM academic_v2_groups g
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        WHERE g.cohort_id = ?
          AND g.stage_number = ?
        ORDER BY g.campus_key ASC, g.id ASC
        LIMIT 1
      `,
      [cohort.id, targetStageNumber]
    );
    return {
      cohortId: Number(cohort.id || 0),
      currentStageNumber,
      targetStageNumber,
      groupIds: affectedGroupIds,
      row: firstTargetCourse,
    };
  });
  return {
    ...result,
    ...(await runProjectionSyncSafely(store, result.groupIds, 'academicV2.promoteCohortStage')),
  };
}

async function saveGroupSubject(store, payload = {}) {
  const result = await withStoreTransaction(store, async (tx) => {
    const groupSubjectId = normalizePositiveInt(payload.group_subject_id || payload.id);
    const groupId = normalizePositiveInt(payload.group_id);
    const subjectTemplateId = normalizePositiveInt(payload.subject_template_id);
    if (!groupId || !subjectTemplateId) {
      throw new Error('GROUP_SUBJECT_TARGET_REQUIRED');
    }
    const template = await tx.get(
      'SELECT id, name FROM academic_v2_subject_templates WHERE id = ? LIMIT 1',
      [subjectTemplateId]
    );
    if (!template) {
      throw new Error('SUBJECT_TEMPLATE_NOT_FOUND');
    }
    const title = cleanText(payload.title, 160) || cleanText(template.name, 160);
    let row;
    if (groupSubjectId) {
      row = await tx.get(
        `
          UPDATE academic_v2_group_subjects
          SET
            group_id = ?,
            subject_template_id = ?,
            title = ?,
            group_count = ?,
            default_group = ?,
            is_visible = ?,
            is_required = ?,
            is_general = ?,
            show_in_teamwork = ?,
            sort_order = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [
          groupId,
          subjectTemplateId,
          title,
          Math.max(1, Number(payload.group_count || 0) || 1),
          Math.max(1, Number(payload.default_group || 0) || 1),
          normalizeBoolean(payload.is_visible, true),
          normalizeBoolean(payload.is_required, true),
          normalizeBoolean(payload.is_general, true),
          normalizeBoolean(payload.show_in_teamwork, true),
          normalizeSortOrder(payload.sort_order, 0),
          groupSubjectId,
        ]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_group_subjects
            (group_id, subject_template_id, title, group_count, default_group, is_visible, is_required, is_general, show_in_teamwork, sort_order, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [
          groupId,
          subjectTemplateId,
          title,
          Math.max(1, Number(payload.group_count || 0) || 1),
          Math.max(1, Number(payload.default_group || 0) || 1),
          normalizeBoolean(payload.is_visible, true),
          normalizeBoolean(payload.is_required, true),
          normalizeBoolean(payload.is_general, true),
          normalizeBoolean(payload.show_in_teamwork, true),
          normalizeSortOrder(payload.sort_order, 0),
        ]
      );
    }
    await tx.run('DELETE FROM academic_v2_group_subject_terms WHERE group_subject_id = ?', [row.id]);
    for (const termId of normalizeIdArray(payload.term_ids || [])) {
      await tx.run(
        `
          INSERT INTO academic_v2_group_subject_terms (group_subject_id, term_id, created_at)
          VALUES (?, ?, NOW())
          ON CONFLICT (group_subject_id, term_id) DO NOTHING
        `,
        [row.id, termId]
      );
    }
    await tx.run('DELETE FROM academic_v2_teacher_assignments WHERE group_subject_id = ?', [row.id]);
    const teacherIds = normalizeIdArray(payload.teacher_ids || []);
    for (let index = 0; index < teacherIds.length; index += 1) {
      await tx.run(
        `
          INSERT INTO academic_v2_teacher_assignments
            (group_subject_id, user_id, is_primary, created_at, updated_at)
          VALUES (?, ?, ?, NOW(), NOW())
        `,
        [row.id, teacherIds[index], index === 0]
      );
    }
    await ensureGroupSubjectBaselineActivityTx(tx, row.id);
    return { row };
  });
  return {
    ...result,
    ...(await runProjectionSyncSafely(store, result && result.row && result.row.group_id, 'academicV2.saveGroupSubject')),
  };
}

async function deleteGroupSubject(store, groupSubjectId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT gs.id, gs.group_id, gs.legacy_subject_id, c.legacy_admission_id
        FROM academic_v2_group_subjects gs
        JOIN academic_v2_groups g ON g.id = gs.group_id
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        WHERE gs.id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(groupSubjectId)]
    );
    if (!row) {
      throw new Error('GROUP_SUBJECT_NOT_FOUND');
    }
    await deleteScheduleRowsForGroupSubjectTx(tx, row.id);
    await hideLegacySubject(tx, row.legacy_admission_id, row.legacy_subject_id);
    await tx.run('DELETE FROM academic_v2_group_subjects WHERE id = ?', [row.id]);
    return { row };
  });
}

async function saveGroupSubjectActivity(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
    const activityId = normalizePositiveInt(payload.group_subject_activity_id || payload.id);
    const groupSubjectId = normalizePositiveInt(payload.group_subject_id);
    if (!groupSubjectId) {
      throw new Error('GROUP_SUBJECT_NOT_FOUND');
    }
    const groupSubject = await tx.get(
      `
        SELECT id, group_id, group_count
        FROM academic_v2_group_subjects
        WHERE id = ?
        LIMIT 1
      `,
      [groupSubjectId]
    );
    if (!groupSubject) {
      throw new Error('GROUP_SUBJECT_NOT_FOUND');
    }
    const activityType = normalizeActivityType(payload.activity_type, 'lecture');
    const sortOrder = normalizeSortOrder(payload.sort_order, ACTIVITY_ORDER[activityType] || 0);
    const existingActivity = activityId
      ? await tx.get(
        'SELECT id FROM academic_v2_group_subject_activities WHERE id = ? LIMIT 1',
        [activityId]
      )
      : null;
    if (activityId && !existingActivity) {
      throw new Error('GROUP_SUBJECT_ACTIVITY_NOT_FOUND');
    }
    const conflictingActivity = activityId
      ? await tx.get(
        `
          SELECT id
          FROM academic_v2_group_subject_activities
          WHERE group_subject_id = ?
            AND activity_type = ?
            AND id <> ?
          LIMIT 1
        `,
        [groupSubjectId, activityType, activityId]
      )
      : await tx.get(
        `
          SELECT id
          FROM academic_v2_group_subject_activities
          WHERE group_subject_id = ?
            AND activity_type = ?
          LIMIT 1
        `,
        [groupSubjectId, activityType]
      );
    if (conflictingActivity) {
      throw new Error('GROUP_SUBJECT_ACTIVITY_DUPLICATE');
    }
    let row;
    if (existingActivity) {
      row = await tx.get(
        `
          UPDATE academic_v2_group_subject_activities
          SET
            group_subject_id = ?,
            activity_type = ?,
            sort_order = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [groupSubjectId, activityType, sortOrder, existingActivity.id]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_group_subject_activities
            (group_subject_id, activity_type, sort_order, created_at, updated_at)
          VALUES (?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [groupSubjectId, activityType, sortOrder]
      );
    }
    return {
      row: {
        ...row,
        group_id: Number(groupSubject.group_id || 0),
        group_count: Math.max(1, Number(groupSubject.group_count || 0) || 1),
      },
    };
  });
}

async function deleteGroupSubjectActivity(store, groupSubjectActivityId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT activity.*, subject.group_id
        FROM academic_v2_group_subject_activities activity
        JOIN academic_v2_group_subjects subject ON subject.id = activity.group_subject_id
        WHERE activity.id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(groupSubjectActivityId)]
    );
    if (!row) {
      throw new Error('GROUP_SUBJECT_ACTIVITY_NOT_FOUND');
    }
    const remainingActivity = await tx.get(
      `
        SELECT id
        FROM academic_v2_group_subject_activities
        WHERE group_subject_id = ?
          AND id <> ?
        LIMIT 1
      `,
      [normalizePositiveInt(row.group_subject_id), row.id]
    );
    if (!remainingActivity) {
      throw new Error('GROUP_SUBJECT_ACTIVITY_REQUIRED');
    }
    await deleteScheduleRowsForActivityTx(tx, row.id);
    await tx.run('DELETE FROM academic_v2_group_subject_activities WHERE id = ?', [row.id]);
    return { row };
  });
}

async function applyGroupSubjectActivityPreset(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
    const groupSubjectId = normalizePositiveInt(payload.group_subject_id);
    if (!groupSubjectId) {
      throw new Error('GROUP_SUBJECT_NOT_FOUND');
    }
    const groupSubject = await tx.get(
      `
        SELECT id, group_id
        FROM academic_v2_group_subjects
        WHERE id = ?
        LIMIT 1
      `,
      [groupSubjectId]
    );
    if (!groupSubject) {
      throw new Error('GROUP_SUBJECT_NOT_FOUND');
    }
    const activityTypes = resolveSubjectActivityPresetTypes(payload.preset_key);
    for (const activityType of activityTypes) {
      const existing = await tx.get(
        `
          SELECT id
          FROM academic_v2_group_subject_activities
          WHERE group_subject_id = ?
            AND activity_type = ?
          LIMIT 1
        `,
        [groupSubjectId, activityType]
      );
      if (existing) {
        continue;
      }
      await tx.run(
        `
          INSERT INTO academic_v2_group_subject_activities
            (group_subject_id, activity_type, sort_order, created_at, updated_at)
          VALUES (?, ?, ?, NOW(), NOW())
        `,
        [groupSubjectId, activityType, ACTIVITY_ORDER[activityType] || 0]
      );
    }
    return {
      row: {
        id: groupSubjectId,
        group_id: Number(groupSubject.group_id || 0),
      },
    };
  });
}

async function bulkAssignUsersToGroup(store, payload = {}) {
  const result = await withStoreTransaction(store, async (tx) => {
    const groupId = normalizePositiveInt(payload.group_id);
    const userIds = normalizeIdArray(payload.user_ids || []);
    if (!groupId || !userIds.length) {
      throw new Error('USER_ASSIGNMENT_TARGET_REQUIRED');
    }
    const group = await tx.get(
      `
        SELECT g.id, g.cohort_id, c.program_id
        FROM academic_v2_groups g
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        WHERE g.id = ?
        LIMIT 1
      `,
      [groupId]
    );
    if (!group) {
      throw new Error('GROUP_REQUIRED');
    }
    for (const userId of userIds) {
      await tx.run('DELETE FROM academic_v2_student_enrollments WHERE user_id = ?', [userId]);
      await tx.run(
        `
          INSERT INTO academic_v2_student_enrollments
            (group_id, user_id, is_primary, created_at, updated_at)
          VALUES (?, ?, TRUE, NOW(), NOW())
        `,
        [groupId, userId]
      );
    }
    return { groupId, userIds, group };
  });
  return {
    ...result,
    ...(await runProjectionSyncSafely(store, result && result.groupId, 'academicV2.bulkAssignUsersToGroup')),
  };
}

async function saveScheduleEntry(store, payload = {}) {
  const result = await withStoreTransaction(store, async (tx) => {
    const scheduleEntryId = normalizePositiveInt(payload.schedule_entry_id || payload.id);
    const groupSubjectActivityId = normalizePositiveInt(payload.group_subject_activity_id || payload.activity_id);
    const termId = normalizePositiveInt(payload.term_id);
    if (!groupSubjectActivityId || !termId) {
      throw new Error('SCHEDULE_TARGET_REQUIRED');
    }
    const activity = await tx.get(
      `
        SELECT
          activity.id,
          activity.group_subject_id,
          activity.activity_type,
          subject.group_id,
          subject.group_count,
          subject.default_group
        FROM academic_v2_group_subject_activities activity
        JOIN academic_v2_group_subjects subject ON subject.id = activity.group_subject_id
        WHERE activity.id = ?
        LIMIT 1
      `,
      [groupSubjectActivityId]
    );
    if (!activity) {
      throw new Error('GROUP_SUBJECT_ACTIVITY_NOT_FOUND');
    }
    const term = await tx.get(
      `
        SELECT id, group_id
        FROM academic_v2_terms
        WHERE id = ?
        LIMIT 1
      `,
      [termId]
    );
    if (!term) {
      throw new Error('TERM_NOT_FOUND');
    }
    if (Number(term.group_id || 0) !== Number(activity.group_id || 0)) {
      throw new Error('SCHEDULE_SCOPE_MISMATCH');
    }
    const activityType = normalizeActivityType(activity.activity_type, 'lecture');
    const requestedGroups = normalizeIdArray(payload.target_group_numbers || payload.group_number || []);
    if (activityType === 'lecture') {
      const invalidLectureOverride = requestedGroups.some((groupNumber) => Number(groupNumber || 0) !== 1);
      if (invalidLectureOverride) {
        throw new Error('SCHEDULE_LECTURE_GROUPS_LOCKED');
      }
    }
    const invalidGroupNumbers = requestedGroups.filter((groupNumber) => groupNumber > Math.max(1, Number(activity.group_count || 0) || 1));
    if (invalidGroupNumbers.length) {
      throw new Error('SCHEDULE_TARGET_GROUP_INVALID');
    }
    const targetGroupNumbers = deriveScheduleTargetGroups(
      activityType,
      payload.target_group_numbers || payload.group_number || [],
      payload.group_number || activity.default_group || 1,
      activity.group_count
    );
    const derivedGroupNumber = deriveScheduleGroupNumber(activityType, targetGroupNumbers, payload.group_number || activity.default_group || 1);
    let row;
    if (scheduleEntryId) {
      row = await tx.get(
        `
          UPDATE academic_v2_schedule_entries
          SET
            group_subject_id = ?,
            group_subject_activity_id = ?,
            term_id = ?,
            group_number = ?,
            target_group_numbers = ?,
            day_of_week = ?,
            class_number = ?,
            week_number = ?,
            lesson_type = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [
          Number(activity.group_subject_id || 0),
          groupSubjectActivityId,
          termId,
          derivedGroupNumber,
          activityType === 'lecture' ? [] : targetGroupNumbers,
          normalizeDayOfWeek(payload.day_of_week, 'Monday'),
          Math.max(1, Number(payload.class_number || 0) || 1),
          Math.max(1, Number(payload.week_number || 0) || 1),
          activityType,
          scheduleEntryId,
        ]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_schedule_entries
            (group_subject_id, group_subject_activity_id, term_id, group_number, target_group_numbers, day_of_week, class_number, week_number, lesson_type, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [
          Number(activity.group_subject_id || 0),
          groupSubjectActivityId,
          termId,
          derivedGroupNumber,
          activityType === 'lecture' ? [] : targetGroupNumbers,
          normalizeDayOfWeek(payload.day_of_week, 'Monday'),
          Math.max(1, Number(payload.class_number || 0) || 1),
          Math.max(1, Number(payload.week_number || 0) || 1),
          activityType,
        ]
      );
    }
    return { row, groupId: Number(activity.group_id || 0) };
  });
  return {
    ...result,
    ...(await runProjectionSyncSafely(store, result && result.groupId, 'academicV2.saveScheduleEntry')),
  };
}

async function deleteScheduleEntry(store, scheduleEntryId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT se.id, gs.group_id
        FROM academic_v2_schedule_entries se
        JOIN academic_v2_group_subject_activities activity ON activity.id = se.group_subject_activity_id
        JOIN academic_v2_group_subjects gs ON gs.id = activity.group_subject_id
        WHERE se.id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(scheduleEntryId)]
    );
    if (!row) {
      throw new Error('SCHEDULE_ENTRY_NOT_FOUND');
    }
    await deleteLegacyScheduleProjectionForEntryTx(tx, row.id);
    await tx.run('DELETE FROM academic_v2_schedule_entries WHERE id = ?', [row.id]);
    return { row };
  });
}

function buildCleanupIssueCodes(projectionIssues = {}) {
  const issues = [];
  if (projectionIssues && projectionIssues.missing_scope) {
    issues.push('missing_scope');
  }
  if (projectionIssues && projectionIssues.missing_active_term) {
    issues.push('missing_active_term');
  }
  if (projectionIssues && projectionIssues.missing_legacy_course) {
    issues.push('missing_legacy_course');
  }
  if (projectionIssues && projectionIssues.missing_legacy_semester) {
    issues.push('missing_legacy_semester');
  }
  if (projectionIssues && Array.isArray(projectionIssues.unmapped_subjects) && projectionIssues.unmapped_subjects.length) {
    issues.push('unmapped_subjects');
  }
  if (projectionIssues && Array.isArray(projectionIssues.unmapped_schedule_entries) && projectionIssues.unmapped_schedule_entries.length) {
    issues.push('unmapped_schedule_entries');
  }
  return issues;
}

async function buildUserNormalizationPreview(store, options = {}) {
  const limit = normalizeCleanupLimit(options.limit, 100, 500);
  const candidates = await store.all(
    `
      SELECT
        id,
        full_name,
        role,
        group_id,
        course_id,
        study_context_id,
        admission_id,
        study_program_id,
        study_track,
        schedule_group
      FROM users
      WHERE role IN ('student', 'starosta')
        AND ${sqlTruthyExpr('is_active', true)}
      ORDER BY full_name ASC NULLS LAST, id ASC
      LIMIT ${limit}
    `
  );
  const userIds = (candidates || [])
    .map((row) => normalizePositiveInt(row.id))
    .filter((value) => Number.isInteger(value) && value > 0);
  const enrollmentRows = userIds.length
    ? await store.all(
      `
        SELECT user_id, group_id, is_primary
        FROM academic_v2_student_enrollments
        WHERE user_id = ANY(?::int[])
        ORDER BY user_id ASC, is_primary DESC, group_id ASC
      `,
      [userIds]
    )
    : [];
  const enrollmentByUserId = new Map();
  for (const row of enrollmentRows || []) {
    const userId = normalizePositiveInt(row.user_id);
    if (!userId || enrollmentByUserId.has(userId)) {
      continue;
    }
    enrollmentByUserId.set(userId, {
      user_id: userId,
      group_id: normalizePositiveInt(row.group_id),
      is_primary: normalizeBoolean(row.is_primary, false),
    });
  }

  const updates = [];
  const unresolved = [];
  const alreadyAligned = [];

  for (const user of candidates || []) {
    const normalizedUserId = normalizePositiveInt(user.id);
    if (!normalizedUserId) continue;
    const scopeState = await academicV2StudentHelpers.resolveStudentAcademicScope(store, user);
    const scope = scopeState && scopeState.scope ? scopeState.scope : null;
    const enrollment = enrollmentByUserId.get(normalizedUserId) || null;
    const issueCodes = buildCleanupIssueCodes(scopeState && scopeState.projectionIssues ? scopeState.projectionIssues : {});
    if (!scope) {
      unresolved.push({
        user_id: normalizedUserId,
        full_name: cleanText(user.full_name, 160),
        role: cleanText(user.role, 40),
        current_group_id: normalizePositiveInt(user.group_id),
        current_course_id: normalizePositiveInt(user.course_id),
        current_study_context_id: normalizePositiveInt(user.study_context_id),
        issue_codes: issueCodes.length ? issueCodes : ['missing_scope'],
      });
      continue;
    }

    const targetGroupId = normalizePositiveInt(scope.group_id);
    const targetCourseId = normalizePositiveInt(scope.legacy_course_id);
    const currentGroupId = normalizePositiveInt(user.group_id);
    const currentCourseId = normalizePositiveInt(user.course_id);
    const currentEnrollmentGroupId = normalizePositiveInt(enrollment && enrollment.group_id);
    const willSetGroupId = Number(currentGroupId || 0) !== Number(targetGroupId || 0);
    const willAlignCourseId = Boolean(targetCourseId) && Number(currentCourseId || 0) !== Number(targetCourseId || 0);
    const willRefreshEnrollment = Number(currentEnrollmentGroupId || 0) !== Number(targetGroupId || 0)
      || !(enrollment && enrollment.is_primary);
    const normalizedRow = {
      user_id: normalizedUserId,
      full_name: cleanText(user.full_name, 160),
      role: cleanText(user.role, 40),
      current_group_id: currentGroupId,
      current_course_id: currentCourseId,
      current_study_context_id: normalizePositiveInt(user.study_context_id),
      current_enrollment_group_id: currentEnrollmentGroupId,
      target_group_id: targetGroupId,
      target_group_label: cleanText(scope.group_label, 160),
      target_stage_number: normalizeCourseStageNumber(scope.stage_number, 1),
      target_campus_key: cleanText(scope.campus_key, 20) || 'kyiv',
      target_course_id: targetCourseId,
      target_program_id: normalizePositiveInt(scope.program_id),
      target_admission_id: normalizePositiveInt(scope.legacy_admission_id),
      resolved_via: cleanText(scope.resolved_via, 40),
      issue_codes: issueCodes,
      will_set_group_id: willSetGroupId,
      will_align_course_id: willAlignCourseId,
      will_refresh_enrollment: willRefreshEnrollment,
    };

    if (!willSetGroupId && !willAlignCourseId && !willRefreshEnrollment) {
      alreadyAligned.push(normalizedRow);
      continue;
    }
    updates.push(normalizedRow);
  }

  return {
    limit,
    total_candidates: Array.isArray(candidates) ? candidates.length : 0,
    resolved_candidates: updates.length + alreadyAligned.length,
    pending_updates: updates.length,
    already_aligned: alreadyAligned.length,
    unresolved_count: unresolved.length,
    will_set_group_id: updates.filter((item) => item.will_set_group_id).length,
    will_align_course_id: updates.filter((item) => item.will_align_course_id).length,
    will_refresh_enrollment: updates.filter((item) => item.will_refresh_enrollment).length,
    affected_group_count: new Set(updates.map((item) => Number(item.target_group_id || 0)).filter((value) => value > 0)).size,
    updates,
    unresolved,
    alreadyAligned,
  };
}

async function normalizeUsersIntoAcademicV2Groups(store, options = {}) {
  const preview = await buildUserNormalizationPreview(store, options);
  if (!normalizeBoolean(options.apply, false)) {
    return {
      mode: 'dry-run',
      ...preview,
    };
  }
  const result = await withStoreTransaction(store, async (tx) => {
    const affectedGroupIds = new Set();
    const appliedUserIds = [];
    for (const update of preview.updates || []) {
      const userId = normalizePositiveInt(update.user_id);
      const groupId = normalizePositiveInt(update.target_group_id);
      if (!userId || !groupId) continue;
      await tx.run('DELETE FROM academic_v2_student_enrollments WHERE user_id = ?', [userId]);
      await tx.run(
        `
          INSERT INTO academic_v2_student_enrollments
            (group_id, user_id, is_primary, created_at, updated_at)
          VALUES (?, ?, TRUE, NOW(), NOW())
        `,
        [groupId, userId]
      );
      affectedGroupIds.add(groupId);
      appliedUserIds.push(userId);
    }
    for (const groupId of affectedGroupIds) {
      await syncGroupProjection(tx, groupId);
    }
    return {
      appliedUserIds,
      affectedGroupIds: Array.from(affectedGroupIds),
    };
  });
  return {
    mode: 'apply',
    ...preview,
    applied_user_count: Array.isArray(result.appliedUserIds) ? result.appliedUserIds.length : 0,
    applied_user_ids: Array.isArray(result.appliedUserIds) ? result.appliedUserIds : [],
    applied_group_count: Array.isArray(result.affectedGroupIds) ? result.affectedGroupIds.length : 0,
    applied_group_ids: Array.isArray(result.affectedGroupIds) ? result.affectedGroupIds : [],
  };
}

async function archiveStaleLegacyAcademicConfig(store, options = {}) {
  const limit = normalizeCleanupLimit(options.limit, 100, 500);
  const preview = {
    staleStudyContexts: await listStaleStudyContextRows(store, limit),
    staleProgramPresets: await listStaleProgramPresetRows(store, limit),
    staleLegacyOfferings: await listStaleLegacyOfferingRows(store, limit),
  };
  const summary = {
    limit,
    stale_study_context_count: Array.isArray(preview.staleStudyContexts) ? preview.staleStudyContexts.length : 0,
    stale_program_preset_count: Array.isArray(preview.staleProgramPresets) ? preview.staleProgramPresets.length : 0,
    stale_legacy_offering_count: Array.isArray(preview.staleLegacyOfferings) ? preview.staleLegacyOfferings.length : 0,
  };
  if (!normalizeBoolean(options.apply, false)) {
    return {
      mode: 'dry-run',
      ...summary,
      ...preview,
    };
  }
  const result = await withStoreTransaction(store, async (tx) => {
    const studyContexts = await listStaleStudyContextRows(tx);
    const programPresets = await listStaleProgramPresetRows(tx);
    const legacyOfferings = await listStaleLegacyOfferingRows(tx);
    const studyContextIds = (studyContexts || [])
      .map((row) => normalizePositiveInt(row.id))
      .filter((value) => Number.isInteger(value) && value > 0);
    const presetIds = (programPresets || [])
      .map((row) => normalizePositiveInt(row.id))
      .filter((value) => Number.isInteger(value) && value > 0);
    const offeringIds = (legacyOfferings || [])
      .map((row) => normalizePositiveInt(row.id))
      .filter((value) => Number.isInteger(value) && value > 0);

    if (studyContextIds.length) {
      await tx.run(
        `
          UPDATE study_contexts
          SET is_active = FALSE,
              updated_at = NOW()
          WHERE id = ANY(?::int[])
        `,
        [studyContextIds]
      );
      await tx.run(
        `
          UPDATE study_context_semesters
          SET is_active = FALSE,
              is_archived = TRUE,
              updated_at = NOW()
          WHERE study_context_id = ANY(?::int[])
        `,
        [studyContextIds]
      );
    }

    if (presetIds.length) {
      await tx.run(
        `
          UPDATE program_presets
          SET is_active = FALSE,
              updated_at = NOW()
          WHERE id = ANY(?::int[])
        `,
        [presetIds]
      );
      await tx.run(
        `
          UPDATE program_preset_stages
          SET is_active = FALSE,
              updated_at = NOW()
          WHERE preset_id = ANY(?::int[])
        `,
        [presetIds]
      );
      await tx.run(
        `
          UPDATE program_preset_semesters
          SET is_active = FALSE,
              is_archived = TRUE,
              updated_at = NOW()
          WHERE preset_stage_id IN (
            SELECT id
            FROM program_preset_stages
            WHERE preset_id = ANY(?::int[])
          )
        `,
        [presetIds]
      );
    }

    if (offeringIds.length) {
      await tx.run(
        `
          UPDATE subject_offerings
          SET is_active = FALSE,
              updated_at = NOW()
          WHERE id = ANY(?::int[])
        `,
        [offeringIds]
      );
      await tx.run(
        `
          UPDATE subject_offering_semesters
          SET is_active = FALSE,
              updated_at = NOW()
          WHERE subject_offering_id = ANY(?::int[])
        `,
        [offeringIds]
      );
    }

    return {
      archivedStudyContextIds: studyContextIds,
      archivedProgramPresetIds: presetIds,
      archivedLegacyOfferingIds: offeringIds,
    };
  });
  return {
    mode: 'apply',
    ...summary,
    ...preview,
    archived_study_context_count: Array.isArray(result.archivedStudyContextIds) ? result.archivedStudyContextIds.length : 0,
    archived_program_preset_count: Array.isArray(result.archivedProgramPresetIds) ? result.archivedProgramPresetIds.length : 0,
    archived_legacy_offering_count: Array.isArray(result.archivedLegacyOfferingIds) ? result.archivedLegacyOfferingIds.length : 0,
    archived_study_context_ids: Array.isArray(result.archivedStudyContextIds) ? result.archivedStudyContextIds : [],
    archived_program_preset_ids: Array.isArray(result.archivedProgramPresetIds) ? result.archivedProgramPresetIds : [],
    archived_legacy_offering_ids: Array.isArray(result.archivedLegacyOfferingIds) ? result.archivedLegacyOfferingIds : [],
  };
}

async function resyncGroupProjection(store, groupId) {
  return withStoreTransaction(store, async (tx) => {
    const normalizedGroupId = normalizePositiveInt(groupId);
    if (!normalizedGroupId) {
      throw new Error('GROUP_REQUIRED');
    }
    await syncGroupProjection(tx, normalizedGroupId);
    return { groupId: normalizedGroupId };
  });
}

async function resyncAllGroupProjections(store) {
  return withStoreTransaction(store, async (tx) => {
    const groupRows = await tx.all('SELECT id FROM academic_v2_groups ORDER BY id ASC');
    for (const row of groupRows || []) {
      const normalizedGroupId = normalizePositiveInt(row.id);
      if (!normalizedGroupId) continue;
      await syncGroupProjection(tx, normalizedGroupId);
    }
    return {
      groupCount: Array.isArray(groupRows) ? groupRows.length : 0,
    };
  });
}

module.exports = {
  loadAcademicAuditSnapshot,
  loadAcademicCleanupDetails,
  loadAcademicSetupPage,
  loadActivityIntegrityReport,
  buildAcademicSetupPageFallback,
  deleteProgram,
  saveProgram,
  deleteCohort,
  saveCohort,
  deleteGroup,
  saveGroup,
  saveTerm,
  deleteTerm,
  deleteSubjectTemplate,
  saveSubjectTemplate,
  saveProgramStageTermTemplate,
  deleteProgramStageTermTemplate,
  saveProgramStageSubjectTemplate,
  deleteProgramStageSubjectTemplate,
  saveProgramStageSubjectActivity,
  deleteProgramStageSubjectActivity,
  applyProgramStageSubjectActivityPreset,
  applyStageTemplateToGroup,
  promoteCohortStage,
  saveGroupSubject,
  deleteGroupSubject,
  saveGroupSubjectActivity,
  deleteGroupSubjectActivity,
  applyGroupSubjectActivityPreset,
  listRegistrationCatalogGroups,
  listRegistrationGroupAuditIssues,
  listRegistrationReadyGroups,
  bulkAssignUsersToGroup,
  normalizeUsersIntoAcademicV2Groups,
  archiveStaleLegacyAcademicConfig,
  saveScheduleEntry,
  deleteScheduleEntry,
  resyncGroupProjection,
  resyncAllGroupProjections,
};
