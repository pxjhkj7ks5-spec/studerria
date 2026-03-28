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
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1;
  const normalized = String(value || '').trim().toLowerCase();
  if (['1', 'true', 'on', 'yes'].includes(normalized)) return true;
  if (['0', 'false', 'off', 'no'].includes(normalized)) return false;
  return fallback === true;
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

function normalizeWeeksCount(value, fallback = 16) {
  const normalized = Number(value || 0);
  if (Number.isInteger(normalized) && normalized > 0) {
    return normalized;
  }
  return Number(fallback || 16) > 0 ? Number(fallback || 16) : 16;
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
    groupId = scopedGroups[0] ? Number(scopedGroups[0].id || 0) : null;
  }

  const scopedTerms = terms.filter((item) => Number(item.group_id || 0) === Number(groupId || 0));
  let termId = normalizePositiveInt(rawFocus.termId);
  if (!scopedTerms.some((item) => Number(item.id) === Number(termId || 0))) {
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
    stage_number: Number(row.stage_number || 0) || 1,
    term_count: Number(row.term_count || 0),
    group_subject_count: Number(row.group_subject_count || 0),
    enrolled_users: Number(row.enrolled_users || 0),
    legacy_course_id: normalizePositiveInt(row.legacy_course_id),
    legacy_study_context_id: normalizePositiveInt(row.legacy_study_context_id),
    is_active: row.is_active === true || Number(row.is_active) === 1,
    track_key: normalizeTrackKey(row.track_key, 'bachelor'),
    campus_key: normalizeCampusKey(row.campus_key, 'kyiv'),
  }));
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
        ) AS teacher_names
      FROM academic_v2_group_subjects gs
      JOIN academic_v2_subject_templates st ON st.id = gs.subject_template_id
      LEFT JOIN academic_v2_group_subject_terms gst ON gst.group_subject_id = gs.id
      LEFT JOIN academic_v2_terms term ON term.id = gst.term_id
      LEFT JOIN academic_v2_teacher_assignments ta ON ta.group_subject_id = gs.id
      LEFT JOIN users teacher ON teacher.id = ta.user_id
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
  }));
}

async function listScheduleEntries(store) {
  const rows = await store.all(
    `
      SELECT
        se.*,
        gs.group_id,
        gs.title AS subject_title,
        st.name AS template_name,
        t.term_number,
        t.title AS term_title
      FROM academic_v2_schedule_entries se
      JOIN academic_v2_group_subjects gs ON gs.id = se.group_subject_id
      JOIN academic_v2_subject_templates st ON st.id = gs.subject_template_id
      JOIN academic_v2_terms t ON t.id = se.term_id
      ORDER BY gs.group_id ASC, t.term_number ASC, se.day_of_week ASC, se.class_number ASC, se.week_number ASC, se.id ASC
    `
  );
  return (rows || []).map((row) => ({
    ...row,
    id: Number(row.id || 0),
    group_id: Number(row.group_id || 0),
    group_subject_id: Number(row.group_subject_id || 0),
    term_id: Number(row.term_id || 0),
    group_number: Math.max(1, Number(row.group_number || 0) || 1),
    class_number: Math.max(1, Number(row.class_number || 0) || 1),
    week_number: Math.max(1, Number(row.week_number || 0) || 1),
    term_number: Number(row.term_number || 0) || 1,
    legacy_schedule_entry_id: normalizePositiveInt(row.legacy_schedule_entry_id),
    day_of_week: normalizeDayOfWeek(row.day_of_week, 'Monday'),
    lesson_type: cleanText(row.lesson_type, 40) || 'lecture',
  })).sort(sortScheduleEntries);
}

async function listTeacherOptions(store) {
  const rows = await store.all(
    `
      SELECT id, full_name
      FROM users
      WHERE role = 'teacher'
        AND COALESCE(CAST(is_active AS INTEGER), 1) = 1
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
      WHERE COALESCE(CAST(u.is_active AS INTEGER), 1) = 1
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
            AND term.is_active = TRUE
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
          JOIN academic_v2_group_subjects subject ON subject.id = entry.group_subject_id
          WHERE subject.group_id = g.id
        ) AS schedule_count,
        (
          SELECT COUNT(*)::int
          FROM academic_v2_schedule_entries entry
          JOIN academic_v2_group_subjects subject ON subject.id = entry.group_subject_id
          WHERE subject.group_id = g.id
            AND entry.legacy_schedule_entry_id IS NOT NULL
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
            AND COALESCE(CAST(u.is_active AS INTEGER), 1) = 1
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

async function buildCleanupAuditSummary(store) {
  const [
    usersWithoutGroupRow,
    usersWithCourseMismatchRow,
    groupsWithoutActiveTermRow,
    groupSubjectsWithoutTeacherRow,
    staleLegacyCourseRowsRow,
    staleLegacySubjectRowsRow,
    staleLegacySemesterRowsRow,
    staleLegacyScheduleRowsRow,
    staleStudyContextsRow,
    legacyPresetRowsRow,
    staleLegacyOfferingRowsRow,
  ] = await Promise.all([
    store.get(
      `
        SELECT COUNT(*)::int AS count
        FROM users
        WHERE role IN ('student', 'starosta')
          AND COALESCE(CAST(is_active AS INTEGER), 1) = 1
          AND group_id IS NULL
      `
    ),
    store.get(
      `
        SELECT COUNT(*)::int AS count
        FROM users u
        JOIN academic_v2_groups g ON g.id = u.group_id
        WHERE u.role IN ('student', 'starosta')
          AND COALESCE(CAST(u.is_active AS INTEGER), 1) = 1
          AND g.legacy_course_id IS NOT NULL
          AND COALESCE(u.course_id, 0) <> g.legacy_course_id
      `
    ),
    store.get(
      `
        SELECT COUNT(*)::int AS count
        FROM academic_v2_groups g
        WHERE NOT EXISTS (
          SELECT 1
          FROM academic_v2_terms term
          WHERE term.group_id = g.id
            AND term.is_active = TRUE
        )
      `
    ),
    store.get(
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
    store.get(
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
    store.get(
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
    store.get(
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
    store.get(
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
            FROM academic_v2_schedule_entries projected
            WHERE projected.legacy_schedule_entry_id = entry.id
          )
      `
    ),
    store.get(
      `
        SELECT COUNT(*)::int AS count
        FROM study_contexts context
        WHERE NOT EXISTS (
          SELECT 1
          FROM academic_v2_groups g
          WHERE g.legacy_study_context_id = context.id
        )
      `
    ),
    store.get('SELECT COUNT(*)::int AS count FROM program_presets'),
    store.get(
      `
        SELECT COUNT(*)::int AS count
        FROM (
          SELECT offering.id
          FROM subject_offerings offering
          LEFT JOIN subject_offering_contexts offering_context
            ON offering_context.subject_offering_id = offering.id
          LEFT JOIN academic_v2_groups g
            ON g.legacy_study_context_id = offering_context.study_context_id
          GROUP BY offering.id
          HAVING COUNT(g.id) = 0
        ) legacy_rows
      `
    ),
  ]);

  const summary = {
    users_without_group_id: Number(usersWithoutGroupRow?.count || 0),
    users_with_course_projection_mismatch: Number(usersWithCourseMismatchRow?.count || 0),
    groups_without_active_term: Number(groupsWithoutActiveTermRow?.count || 0),
    group_subjects_without_teacher_assignment: Number(groupSubjectsWithoutTeacherRow?.count || 0),
    stale_legacy_course_rows: Number(staleLegacyCourseRowsRow?.count || 0),
    stale_legacy_subject_rows: Number(staleLegacySubjectRowsRow?.count || 0),
    stale_legacy_semester_rows: Number(staleLegacySemesterRowsRow?.count || 0),
    stale_legacy_schedule_rows: Number(staleLegacyScheduleRowsRow?.count || 0),
    stale_legacy_study_context_rows: Number(staleStudyContextsRow?.count || 0),
    legacy_preset_rows: Number(legacyPresetRowsRow?.count || 0),
    stale_legacy_offering_rows: Number(staleLegacyOfferingRowsRow?.count || 0),
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

async function loadAcademicSetupPage(store, focus = {}) {
  const [
    programs,
    cohorts,
    groups,
    terms,
    subjectTemplates,
    groupSubjects,
    scheduleEntries,
    teachers,
    users,
    summary,
    projectionHealth,
    auditSummary,
  ] = await Promise.all([
    listPrograms(store),
    listCohorts(store),
    listGroups(store),
    listTerms(store),
    listSubjectTemplates(store),
    listGroupSubjects(store),
    listScheduleEntries(store),
    listTeacherOptions(store),
    listAssignableUsers(store),
    buildDashboardSummary(store),
    listProjectionHealth(store),
    buildCleanupAuditSummary(store),
  ]);

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

  return {
    summary,
    programs,
    cohorts,
    groups,
    terms,
    subjectTemplates,
    groupSubjects,
    scheduleEntries,
    teachers,
    users,
    projectionHealth: projectionHealth.items,
    projectionHealthSummary: projectionHealth.summary,
    auditSummary,
    selectedProgram,
    selectedCohort,
    selectedGroup,
    selectedTerm,
    focus: resolvedFocus,
    scopedCohorts: cohorts.filter((item) => Number(item.program_id) === Number(resolvedFocus.programId || 0)),
    scopedGroups: groups.filter((item) => Number(item.cohort_id) === Number(resolvedFocus.cohortId || 0)),
    scopedTerms: terms.filter((item) => Number(item.group_id) === Number(resolvedFocus.groupId || 0)),
    scopedGroupSubjects: groupSubjects.filter((item) => Number(item.group_id) === Number(resolvedFocus.groupId || 0)),
    scopedScheduleEntries: scheduleEntries.filter((item) => (
      Number(item.group_id) === Number(resolvedFocus.groupId || 0)
      && (!resolvedFocus.termId || Number(item.term_id) === Number(resolvedFocus.termId || 0))
    )),
  };
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
        normalizeBoolean(term.is_active, false),
        normalizeBoolean(term.is_archived, false),
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
        normalizeBoolean(term.is_active, false),
        normalizeBoolean(term.is_archived, false),
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

async function syncScheduleProjectionForGroup(tx, groupId) {
  const scheduleEntries = await tx.all(
    `
      SELECT se.id, se.group_subject_id, se.term_id, se.group_number, se.day_of_week, se.class_number, se.week_number, se.lesson_type, se.legacy_schedule_entry_id
      FROM academic_v2_schedule_entries se
      JOIN academic_v2_group_subjects gs ON gs.id = se.group_subject_id
      WHERE gs.group_id = ?
      ORDER BY se.id ASC
    `,
    [groupId]
  );
  for (const entry of scheduleEntries || []) {
    const { legacySubjectId, legacyCourseId } = await ensureLegacySubject(tx, Number(entry.group_subject_id));
    const { legacySemesterId } = await ensureLegacyTerm(tx, Number(entry.term_id));
    const existingLegacyScheduleEntryId = normalizePositiveInt(entry.legacy_schedule_entry_id);
    let legacyScheduleEntryId = existingLegacyScheduleEntryId;
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
          Math.max(1, Number(entry.group_number || 0) || 1),
          normalizeDayOfWeek(entry.day_of_week, 'Monday'),
          Math.max(1, Number(entry.class_number || 0) || 1),
          Math.max(1, Number(entry.week_number || 0) || 1),
          legacyCourseId,
          legacySemesterId,
          cleanText(entry.lesson_type, 40) || 'lecture',
        ]
      );
      legacyScheduleEntryId = normalizePositiveInt(inserted && inserted.id);
      await tx.run(
        'UPDATE academic_v2_schedule_entries SET legacy_schedule_entry_id = ?, updated_at = NOW() WHERE id = ?',
        [legacyScheduleEntryId, entry.id]
      );
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
          Math.max(1, Number(entry.group_number || 0) || 1),
          normalizeDayOfWeek(entry.day_of_week, 'Monday'),
          Math.max(1, Number(entry.class_number || 0) || 1),
          Math.max(1, Number(entry.week_number || 0) || 1),
          legacyCourseId,
          legacySemesterId,
          cleanText(entry.lesson_type, 40) || 'lecture',
          legacyScheduleEntryId,
        ]
      );
    }
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
          (SELECT COUNT(*)::int FROM program_admissions WHERE program_id = ?) AS legacy_admission_count,
          (SELECT COUNT(*)::int FROM users WHERE study_program_id = ?) AS user_count
      `,
      [row.id, legacyProgramId, legacyProgramId]
    );
    if (
      Number(dependencyRow?.cohort_count || 0) > 0
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
          (SELECT COUNT(*)::int FROM subjects WHERE catalog_id = ?) AS legacy_subject_count,
          (SELECT COUNT(*)::int FROM program_preset_stage_subjects WHERE subject_catalog_id = ?) AS preset_subject_count,
          (SELECT COUNT(*)::int FROM subject_offerings WHERE subject_catalog_id = ?) AS legacy_offering_count,
          (SELECT COUNT(*)::int FROM teacher_assignment_templates WHERE subject_catalog_id = ?) AS teacher_template_count
      `,
      [row.id, legacyCatalogId, legacyCatalogId, legacyCatalogId, legacyCatalogId]
    );
    if (
      Number(dependencyRow?.group_subject_count || 0) > 0
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
            is_active = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [
          programId,
          admissionYear,
          cleanText(payload.label, 120) || `Cohort ${admissionYear}`,
          normalizeBoolean(payload.is_active, true),
          cohortId,
        ]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_cohorts
            (program_id, admission_year, label, is_active, created_at, updated_at)
          VALUES (?, ?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [programId, admissionYear, cleanText(payload.label, 120) || `Cohort ${admissionYear}`, normalizeBoolean(payload.is_active, true)]
      );
    }
    await ensureLegacyAdmission(tx, Number(row.id));
    return { row };
  });
}

async function saveGroup(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
    const groupId = normalizePositiveInt(payload.group_id || payload.id);
    const cohortId = normalizePositiveInt(payload.cohort_id);
    if (!cohortId) {
      throw new Error('COHORT_REQUIRED');
    }
    const label = cleanText(payload.label, 160);
    if (!label) {
      throw new Error('GROUP_LABEL_REQUIRED');
    }
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
            is_active = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [
          cohortId,
          normalizeStageNumber(payload.stage_number, 1),
          normalizeCampusKey(payload.campus_key, 'kyiv'),
          cleanText(payload.code, 40) || null,
          label,
          normalizeBoolean(payload.is_active, true),
          groupId,
        ]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_groups
            (cohort_id, stage_number, campus_key, code, label, is_active, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [
          cohortId,
          normalizeStageNumber(payload.stage_number, 1),
          normalizeCampusKey(payload.campus_key, 'kyiv'),
          cleanText(payload.code, 40) || null,
          label,
          normalizeBoolean(payload.is_active, true),
        ]
      );
    }
    const enrichedRow = await tx.get(
      `
        SELECT g.*, c.program_id
        FROM academic_v2_groups g
        JOIN academic_v2_cohorts c ON c.id = g.cohort_id
        WHERE g.id = ?
        LIMIT 1
      `,
      [row.id]
    );
    await syncGroupProjection(tx, Number(row.id));
    return { row: enrichedRow || row };
  });
}

async function saveTerm(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
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
    await syncGroupProjection(tx, groupId);
    return { row };
  });
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
    const scheduleRows = await tx.all(
      'SELECT legacy_schedule_entry_id FROM academic_v2_schedule_entries WHERE term_id = ?',
      [row.id]
    );
    for (const scheduleRow of scheduleRows || []) {
      const legacyScheduleEntryId = normalizePositiveInt(scheduleRow.legacy_schedule_entry_id);
      if (legacyScheduleEntryId) {
        await tx.run('DELETE FROM schedule_entries WHERE id = ?', [legacyScheduleEntryId]);
      }
    }
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

async function saveGroupSubject(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
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
    await syncGroupProjection(tx, groupId);
    return { row };
  });
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
    const scheduleRows = await tx.all(
      'SELECT legacy_schedule_entry_id FROM academic_v2_schedule_entries WHERE group_subject_id = ?',
      [row.id]
    );
    for (const scheduleRow of scheduleRows || []) {
      const legacyScheduleEntryId = normalizePositiveInt(scheduleRow.legacy_schedule_entry_id);
      if (legacyScheduleEntryId) {
        await tx.run('DELETE FROM schedule_entries WHERE id = ?', [legacyScheduleEntryId]);
      }
    }
    await hideLegacySubject(tx, row.legacy_admission_id, row.legacy_subject_id);
    await tx.run('DELETE FROM academic_v2_group_subjects WHERE id = ?', [row.id]);
    return { row };
  });
}

async function bulkAssignUsersToGroup(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
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
    await syncGroupProjection(tx, groupId);
    return { groupId, userIds, group };
  });
}

async function saveScheduleEntry(store, payload = {}) {
  return withStoreTransaction(store, async (tx) => {
    const scheduleEntryId = normalizePositiveInt(payload.schedule_entry_id || payload.id);
    const groupSubjectId = normalizePositiveInt(payload.group_subject_id);
    const termId = normalizePositiveInt(payload.term_id);
    if (!groupSubjectId || !termId) {
      throw new Error('SCHEDULE_TARGET_REQUIRED');
    }
    let row;
    if (scheduleEntryId) {
      row = await tx.get(
        `
          UPDATE academic_v2_schedule_entries
          SET
            group_subject_id = ?,
            term_id = ?,
            group_number = ?,
            day_of_week = ?,
            class_number = ?,
            week_number = ?,
            lesson_type = ?,
            updated_at = NOW()
          WHERE id = ?
          RETURNING *
        `,
        [
          groupSubjectId,
          termId,
          Math.max(1, Number(payload.group_number || 0) || 1),
          normalizeDayOfWeek(payload.day_of_week, 'Monday'),
          Math.max(1, Number(payload.class_number || 0) || 1),
          Math.max(1, Number(payload.week_number || 0) || 1),
          cleanText(payload.lesson_type, 40) || 'lecture',
          scheduleEntryId,
        ]
      );
    } else {
      row = await tx.get(
        `
          INSERT INTO academic_v2_schedule_entries
            (group_subject_id, term_id, group_number, day_of_week, class_number, week_number, lesson_type, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
          RETURNING *
        `,
        [
          groupSubjectId,
          termId,
          Math.max(1, Number(payload.group_number || 0) || 1),
          normalizeDayOfWeek(payload.day_of_week, 'Monday'),
          Math.max(1, Number(payload.class_number || 0) || 1),
          Math.max(1, Number(payload.week_number || 0) || 1),
          cleanText(payload.lesson_type, 40) || 'lecture',
        ]
      );
    }
    const groupSubject = await tx.get('SELECT group_id FROM academic_v2_group_subjects WHERE id = ? LIMIT 1', [groupSubjectId]);
    if (!groupSubject) {
      throw new Error('GROUP_SUBJECT_NOT_FOUND');
    }
    await syncGroupProjection(tx, Number(groupSubject.group_id || 0));
    return { row, groupId: Number(groupSubject.group_id || 0) };
  });
}

async function deleteScheduleEntry(store, scheduleEntryId) {
  return withStoreTransaction(store, async (tx) => {
    const row = await tx.get(
      `
        SELECT se.id, se.legacy_schedule_entry_id, gs.group_id
        FROM academic_v2_schedule_entries se
        JOIN academic_v2_group_subjects gs ON gs.id = se.group_subject_id
        WHERE se.id = ?
        LIMIT 1
      `,
      [normalizePositiveInt(scheduleEntryId)]
    );
    if (!row) {
      throw new Error('SCHEDULE_ENTRY_NOT_FOUND');
    }
    const legacyScheduleEntryId = normalizePositiveInt(row.legacy_schedule_entry_id);
    if (legacyScheduleEntryId) {
      await tx.run('DELETE FROM schedule_entries WHERE id = ?', [legacyScheduleEntryId]);
    }
    await tx.run('DELETE FROM academic_v2_schedule_entries WHERE id = ?', [row.id]);
    return { row };
  });
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
  loadAcademicSetupPage,
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
  saveGroupSubject,
  deleteGroupSubject,
  bulkAssignUsersToGroup,
  saveScheduleEntry,
  deleteScheduleEntry,
  resyncGroupProjection,
  resyncAllGroupProjections,
};
