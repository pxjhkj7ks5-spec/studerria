function cleanCompactText(value, maxLength = 160) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, Math.max(1, Number(maxLength) || 1));
}

function normalizeStageNumber(value, fallback = 1) {
  const normalized = Number(value || 0);
  if (Number.isInteger(normalized) && normalized > 0) {
    return normalized;
  }
  const normalizedFallback = Number(fallback || 0);
  return Number.isInteger(normalizedFallback) && normalizedFallback > 0 ? normalizedFallback : 1;
}

function normalizeCampusKey(value, fallback = 'kyiv') {
  return String(value || '').trim().toLowerCase() === 'munich' ? 'munich' : fallback === 'munich' ? 'munich' : 'kyiv';
}

function normalizeTrackKey(value, fallback = 'bachelor') {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'bachelor' || normalized === 'master' || normalized === 'teacher') {
    return normalized;
  }
  const normalizedFallback = String(fallback || '').trim().toLowerCase();
  if (normalizedFallback === 'bachelor' || normalizedFallback === 'master' || normalizedFallback === 'teacher') {
    return normalizedFallback;
  }
  return 'bachelor';
}

function normalizeStageCountByTrack(trackKey, requestedCount) {
  const normalizedTrack = normalizeTrackKey(trackKey, 'bachelor');
  const defaultCount = normalizedTrack === 'master' ? 2 : (normalizedTrack === 'teacher' ? 1 : 4);
  const normalizedCount = Number(requestedCount || 0);
  if (!Number.isInteger(normalizedCount) || normalizedCount < 1) {
    return defaultCount;
  }
  const maxCount = normalizedTrack === 'teacher' ? 1 : 8;
  return Math.max(1, Math.min(normalizedCount, maxCount));
}

function buildStageLabel(stageNumber, trackKey, lang = 'uk') {
  const normalizedStage = normalizeStageNumber(stageNumber, 1);
  const normalizedTrack = normalizeTrackKey(trackKey, 'bachelor');
  if (normalizedTrack === 'teacher') {
    return lang === 'en' ? 'Teacher context' : 'Викладацький контекст';
  }
  return lang === 'en' ? `Year ${normalizedStage}` : `${normalizedStage} курс`;
}

function buildAcademicTrackOrderKey(trackKey) {
  switch (String(trackKey || '').trim().toLowerCase()) {
    case 'bachelor':
      return 0;
    case 'master':
      return 1;
    case 'teacher':
      return 2;
    default:
      return 99;
  }
}

function normalizeSelectableTrack(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return ['bachelor', 'master', 'teacher'].includes(normalized) ? normalized : '';
}

function normalizeSelectableCampus(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized === 'munich' ? 'munich' : (normalized === 'kyiv' ? 'kyiv' : '');
}

function pickScopedValue(source, ...keys) {
  for (const key of keys) {
    if (!key || !source || typeof source !== 'object') continue;
    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
    const value = source[key];
    if (value === null || typeof value === 'undefined' || value === '') continue;
    return value;
  }
  return null;
}

function resolveAdminAcademicScopeState({
  courses = [],
  studyContexts = [],
  storedScope = {},
  requestedScope = {},
  fallbackCourseId = null,
  currentUserCourseId = null,
  allowedCourseIds = null,
  buildStudyContextLabel = null,
  inferTrackFromCourse = null,
} = {}) {
  const normalizedCourses = Array.isArray(courses) ? courses : [];
  const hasScopedCourseFilter = allowedCourseIds instanceof Set || Array.isArray(allowedCourseIds);
  const normalizedAllowedCourseIds = allowedCourseIds instanceof Set
    ? new Set(
      Array.from(allowedCourseIds.values())
        .map((value) => normalizePositiveInt(value))
        .filter((value) => Number.isInteger(value) && value > 0)
    )
    : new Set(
      (Array.isArray(allowedCourseIds) ? allowedCourseIds : [])
        .map((value) => normalizePositiveInt(value))
        .filter((value) => Number.isInteger(value) && value > 0)
    );
  const normalizedStudyContexts = (Array.isArray(studyContexts) ? studyContexts : [])
    .filter((context) => {
      const courseId = normalizePositiveInt(context && context.course_id);
      if (!hasScopedCourseFilter) {
        return true;
      }
      return Boolean(courseId && normalizedAllowedCourseIds.has(courseId));
    })
    .map((context) => ({
      ...context,
      id: normalizePositiveInt(context && context.id),
      course_id: normalizePositiveInt(context && context.course_id),
      program_id: normalizePositiveInt(context && context.program_id),
      admission_id: normalizePositiveInt(context && context.admission_id),
      admission_year: normalizePositiveInt(context && context.admission_year),
      stage: normalizeStageNumber(context && (context.stage || context.stage_number), 1),
      track_key: normalizeTrackKey(context && context.track_key, 'bachelor'),
      campus_key: normalizeCampusKey(context && (context.campus_key || context.course_location), 'kyiv'),
      label: cleanCompactText(
        (context && (context.label || context.label_uk))
          || (typeof buildStudyContextLabel === 'function' ? buildStudyContextLabel(context, 'uk') : ''),
        200
      ),
      label_en: cleanCompactText(
        (context && context.label_en)
          || (typeof buildStudyContextLabel === 'function' ? buildStudyContextLabel(context, 'en') : ''),
        200
      ),
    }))
    .sort((a, b) => {
      const trackDiff = buildAcademicTrackOrderKey(a.track_key) - buildAcademicTrackOrderKey(b.track_key);
      if (trackDiff !== 0) return trackDiff;
      const programDiff = String(a.program_name || a.program_code || '').localeCompare(String(b.program_name || b.program_code || ''), 'uk', { sensitivity: 'base' });
      if (programDiff !== 0) return programDiff;
      const yearDiff = Number(b.admission_year || 0) - Number(a.admission_year || 0);
      if (yearDiff !== 0) return yearDiff;
      const stageDiff = Number(a.stage || 0) - Number(b.stage || 0);
      if (stageDiff !== 0) return stageDiff;
      return String(a.campus_key || '').localeCompare(String(b.campus_key || ''));
    });

  const requestedTrack = normalizeSelectableTrack(
    pickScopedValue(requestedScope, 'track', 'mode')
      || pickScopedValue(storedScope, 'track', 'mode')
  );
  const requestedProgramId = normalizePositiveInt(
    pickScopedValue(requestedScope, 'programId', 'program_id')
      || pickScopedValue(storedScope, 'programId', 'program_id')
  );
  const requestedAdmissionId = normalizePositiveInt(
    pickScopedValue(requestedScope, 'admissionId', 'admission_id')
      || pickScopedValue(storedScope, 'admissionId', 'admission_id')
  );
  const requestedStage = normalizePositiveInt(
    pickScopedValue(requestedScope, 'stage', 'stage_number')
      || pickScopedValue(storedScope, 'stage', 'stage_number')
  );
  const requestedCampus = normalizeSelectableCampus(
    pickScopedValue(requestedScope, 'campus', 'campusKey', 'campus_key')
      || pickScopedValue(storedScope, 'campus', 'campusKey', 'campus_key')
  );
  const requestedStudyContextId = normalizePositiveInt(
    pickScopedValue(requestedScope, 'studyContextId', 'study_context_id')
      || pickScopedValue(storedScope, 'studyContextId', 'study_context_id')
  );
  const requestedCourseId = normalizePositiveInt(
    pickScopedValue(requestedScope, 'courseId', 'course', 'course_id')
      || pickScopedValue(storedScope, 'courseId', 'course', 'course_id')
      || fallbackCourseId
      || currentUserCourseId
      || (normalizedCourses[0] && normalizedCourses[0].id)
  );

  const explicitContext = requestedStudyContextId
    ? (normalizedStudyContexts.find((context) => Number(context.id || 0) === Number(requestedStudyContextId || 0)) || null)
    : null;
  const fallbackCourse = requestedCourseId
    ? (normalizedCourses.find((course) => Number(course.id || 0) === Number(requestedCourseId || 0)) || null)
    : null;
  let selectedTrack = explicitContext
    ? normalizeTrackKey(explicitContext.track_key, 'bachelor')
    : requestedTrack;
  if (!selectedTrack && typeof inferTrackFromCourse === 'function') {
    selectedTrack = normalizeSelectableTrack(inferTrackFromCourse(fallbackCourse));
  }

  const trackSet = Array.from(new Set(
    normalizedStudyContexts
      .map((context) => normalizeTrackKey(context.track_key, 'bachelor'))
      .filter(Boolean)
  ));
  trackSet.sort((a, b) => buildAcademicTrackOrderKey(a) - buildAcademicTrackOrderKey(b));
  if (!trackSet.includes(selectedTrack)) {
    selectedTrack = trackSet[0] || selectedTrack || 'bachelor';
  }

  const trackContexts = normalizedStudyContexts.filter((context) => normalizeTrackKey(context.track_key, 'bachelor') === selectedTrack);
  const programOptions = Array.from(new Map(
    trackContexts
      .map((context) => [Number(context.program_id || 0), {
        id: Number(context.program_id || 0) || null,
        label: context.program_code
          ? `${String(context.program_name || '').trim()} (${String(context.program_code || '').trim()})`
          : String(context.program_name || context.program_code || '').trim(),
      }])
      .filter(([programId]) => Number.isInteger(programId) && programId > 0)
  ).values()).sort((a, b) => String(a.label || '').localeCompare(String(b.label || ''), 'uk', { sensitivity: 'base' }));
  let selectedProgramId = explicitContext && Number(explicitContext.program_id || 0) > 0
    ? Number(explicitContext.program_id || 0)
    : requestedProgramId;
  if (!programOptions.some((option) => Number(option.id || 0) === Number(selectedProgramId || 0))) {
    selectedProgramId = programOptions[0] ? Number(programOptions[0].id || 0) : null;
  }

  const programContexts = trackContexts.filter((context) => Number(context.program_id || 0) === Number(selectedProgramId || 0));
  const admissionOptions = Array.from(new Map(
    programContexts
      .map((context) => [Number(context.admission_id || 0), {
        id: Number(context.admission_id || 0) || null,
        admission_year: Number(context.admission_year || 0) || null,
        label: Number(context.admission_year || 0) || context.admission_id || '',
      }])
      .filter(([admissionId]) => Number.isInteger(admissionId) && admissionId > 0)
  ).values()).sort((a, b) => Number(b.admission_year || 0) - Number(a.admission_year || 0));
  let selectedAdmissionId = explicitContext && Number(explicitContext.admission_id || 0) > 0
    ? Number(explicitContext.admission_id || 0)
    : requestedAdmissionId;
  if (!admissionOptions.some((option) => Number(option.id || 0) === Number(selectedAdmissionId || 0))) {
    selectedAdmissionId = admissionOptions[0] ? Number(admissionOptions[0].id || 0) : null;
  }

  const admissionContexts = programContexts.filter((context) => Number(context.admission_id || 0) === Number(selectedAdmissionId || 0));
  const stageOptions = Array.from(new Map(
    admissionContexts
      .map((context) => {
        const stageNumber = normalizeStageNumber(context.stage, 1);
        return [stageNumber, {
          value: stageNumber,
          label: buildStageLabel(stageNumber, selectedTrack, 'uk'),
        }];
      })
  ).values()).sort((a, b) => Number(a.value || 0) - Number(b.value || 0));
  let selectedStage = explicitContext
    ? normalizeStageNumber(explicitContext.stage, 1)
    : requestedStage;
  if (!stageOptions.some((option) => Number(option.value || 0) === Number(selectedStage || 0))) {
    selectedStage = stageOptions[0] ? Number(stageOptions[0].value || 0) : 1;
  }

  const stageContexts = admissionContexts.filter((context) => normalizeStageNumber(context.stage, 1) === Number(selectedStage || 0));
  const campusOptions = Array.from(new Map(
    stageContexts
      .map((context) => {
        const campusKey = normalizeCampusKey(context.campus_key || context.course_location, 'kyiv');
        return [campusKey, {
          value: campusKey,
          label: campusKey === 'munich' ? 'Munich' : 'Kyiv',
        }];
      })
  ).values()).sort((a, b) => String(a.label || '').localeCompare(String(b.label || '')));
  let selectedCampus = explicitContext
    ? normalizeCampusKey(explicitContext.campus_key || explicitContext.course_location || '', 'kyiv')
    : requestedCampus;
  if (!campusOptions.some((option) => option.value === selectedCampus)) {
    selectedCampus = campusOptions[0]
      ? String(campusOptions[0].value || '')
      : normalizeCampusKey((fallbackCourse && fallbackCourse.location) || '', 'kyiv');
  }

  const scopedContextOptions = stageContexts.filter(
    (context) => normalizeCampusKey(context.campus_key || context.course_location || '', 'kyiv') === selectedCampus
  );
  let selectedContext = explicitContext
    && scopedContextOptions.some((context) => Number(context.id || 0) === Number(explicitContext.id || 0))
    ? explicitContext
    : null;
  if (!selectedContext && requestedStudyContextId) {
    selectedContext = scopedContextOptions.find((context) => Number(context.id || 0) === Number(requestedStudyContextId || 0)) || null;
  }
  if (!selectedContext && requestedCourseId) {
    selectedContext = scopedContextOptions.find((context) => Number(context.course_id || 0) === Number(requestedCourseId || 0)) || null;
  }
  if (!selectedContext && scopedContextOptions.length) {
    selectedContext = scopedContextOptions[0];
  }

  const selectedCourseId = selectedContext && Number(selectedContext.course_id || 0) > 0
    ? Number(selectedContext.course_id || 0)
    : requestedCourseId
      || normalizePositiveInt(fallbackCourseId)
      || normalizePositiveInt(currentUserCourseId)
      || ((normalizedCourses[0] && Number(normalizedCourses[0].id || 0)) || null);
  const selectedCourse = normalizedCourses.find((course) => Number(course.id || 0) === Number(selectedCourseId || 0)) || fallbackCourse || null;
  if (selectedContext) {
    selectedTrack = normalizeTrackKey(selectedContext.track_key, selectedTrack || 'bachelor');
    selectedProgramId = Number(selectedContext.program_id || 0) || selectedProgramId || null;
    selectedAdmissionId = Number(selectedContext.admission_id || 0) || selectedAdmissionId || null;
    selectedStage = normalizeStageNumber(selectedContext.stage, selectedStage || 1);
    selectedCampus = normalizeCampusKey(selectedContext.campus_key || selectedContext.course_location || selectedCampus || '', 'kyiv');
  }

  const trackOptions = trackSet.map((trackKey) => ({
    value: trackKey,
    label: trackKey === 'master' ? 'Masters' : (trackKey === 'teacher' ? 'Teachers' : 'Bachelors'),
  }));
  const selectedProgram = programOptions.find((option) => Number(option.id || 0) === Number(selectedProgramId || 0)) || null;
  const selectedAdmission = admissionOptions.find((option) => Number(option.id || 0) === Number(selectedAdmissionId || 0)) || null;
  const selectedStageOption = stageOptions.find((option) => Number(option.value || 0) === Number(selectedStage || 0)) || null;
  const selectedCampusOption = campusOptions.find((option) => String(option.value || '') === String(selectedCampus || '')) || null;
  const selectedLabel = selectedContext
    ? cleanCompactText(
      selectedContext.label_uk
        || selectedContext.label
        || (typeof buildStudyContextLabel === 'function' ? buildStudyContextLabel(selectedContext, 'uk') : ''),
      200
    )
    : (selectedCourse && selectedCourse.name
      ? String(selectedCourse.name)
      : (selectedProgram ? selectedProgram.label : 'Academic scope'));

  const storedPayload = {
    track: selectedTrack,
    programId: selectedProgramId || null,
    admissionId: selectedAdmissionId || null,
    stage: selectedStage || null,
    campus: selectedCampus || '',
    studyContextId: selectedContext ? Number(selectedContext.id || 0) || null : null,
    courseId: selectedCourseId || null,
  };

  return {
    ...storedPayload,
    label: selectedLabel,
    selectedCourse,
    selectedContext,
    selectedTrackLabel: trackOptions.find((option) => option.value === selectedTrack)?.label || selectedTrack,
    selectedProgramLabel: selectedProgram ? selectedProgram.label : '',
    selectedAdmissionYear: selectedAdmission ? Number(selectedAdmission.admission_year || 0) || null : null,
    selectedStageLabel: selectedStageOption ? selectedStageOption.label : '',
    selectedCampusLabel: selectedCampusOption ? selectedCampusOption.label : (selectedCampus === 'munich' ? 'Munich' : 'Kyiv'),
    trackOptions,
    programOptions,
    admissionOptions,
    stageOptions,
    campusOptions,
    contextOptions: scopedContextOptions,
    availableStudyContexts: normalizedStudyContexts,
    availableCourseIds: hasScopedCourseFilter
      ? Array.from(normalizedAllowedCourseIds.values())
      : normalizedCourses
        .map((course) => Number(course.id || 0))
        .filter((value) => Number.isInteger(value) && value > 0),
  };
}

function buildModerationKey(...parts) {
  return parts
    .map((part) => String(part === null || typeof part === 'undefined' ? '' : part).trim())
    .filter(Boolean)
    .join('::');
}

function normalizeModerationStatus(value, fallback = 'open') {
  const normalized = String(value || '').trim().toLowerCase();
  if (['open', 'reviewing', 'resolved', 'ignored'].includes(normalized)) {
    return normalized;
  }
  return fallback;
}

function normalizeModerationSeverity(value, fallback = 'medium') {
  const normalized = String(value || '').trim().toLowerCase();
  if (['high', 'medium', 'low'].includes(normalized)) {
    return normalized;
  }
  return fallback;
}

async function upsertAcademicModerationItem(store, {
  dedupeKey,
  sourceKind,
  sourceId,
  issueCode,
  severity = 'medium',
  status = 'open',
  title = '',
  summary = '',
  payload = {},
} = {}) {
  if (!store || typeof store.run !== 'function') {
    return null;
  }
  const normalizedDedupeKey = cleanCompactText(dedupeKey, 240);
  const normalizedSourceKind = cleanCompactText(sourceKind, 80);
  const normalizedIssueCode = cleanCompactText(issueCode, 80);
  if (!normalizedDedupeKey || !normalizedSourceKind || !normalizedIssueCode) {
    return null;
  }
  const normalizedSourceId = normalizePositiveInt(sourceId) || null;
  const normalizedSeverity = normalizeModerationSeverity(severity, 'medium');
  const normalizedStatus = normalizeModerationStatus(status, 'open');
  const safePayload = payload && typeof payload === 'object' ? payload : {};
  const payloadJson = JSON.stringify(safePayload);
  await store.run(
    `
      INSERT INTO academic_moderation_queue
        (dedupe_key, source_kind, source_id, issue_code, severity, status, title, summary, payload_json, created_at, updated_at, resolved_at, resolved_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, NOW(), NOW(), CASE WHEN ? IN ('resolved', 'ignored') THEN NOW() ELSE NULL END, NULL)
      ON CONFLICT (dedupe_key)
      DO UPDATE SET
        source_kind = EXCLUDED.source_kind,
        source_id = EXCLUDED.source_id,
        issue_code = EXCLUDED.issue_code,
        severity = EXCLUDED.severity,
        status = EXCLUDED.status,
        title = EXCLUDED.title,
        summary = EXCLUDED.summary,
        payload_json = EXCLUDED.payload_json,
        updated_at = NOW(),
        resolved_at = CASE
          WHEN EXCLUDED.status IN ('resolved', 'ignored') THEN COALESCE(academic_moderation_queue.resolved_at, NOW())
          ELSE NULL
        END,
        resolved_by = CASE
          WHEN EXCLUDED.status IN ('resolved', 'ignored') THEN academic_moderation_queue.resolved_by
          ELSE NULL
        END
    `,
    [
      normalizedDedupeKey,
      normalizedSourceKind,
      normalizedSourceId,
      normalizedIssueCode,
      normalizedSeverity,
      normalizedStatus,
      cleanCompactText(title, 160),
      cleanCompactText(summary, 320),
      payloadJson,
      normalizedStatus,
    ]
  );
  return {
    dedupe_key: normalizedDedupeKey,
    source_kind: normalizedSourceKind,
    source_id: normalizedSourceId,
    issue_code: normalizedIssueCode,
    severity: normalizedSeverity,
    status: normalizedStatus,
    payload: safePayload,
  };
}

function buildRegistrationMissingStageOneIssue({
  userId,
  programId = null,
  admissionId = null,
  trackKey = null,
  campusKey = null,
  stageNumber = 1,
  courseId = null,
  studyContextId = null,
  dedupeSuffix = '',
  title = '',
  summary = '',
} = {}) {
  const normalizedUserId = normalizePositiveInt(userId);
  const normalizedAdmissionId = normalizePositiveInt(admissionId) || 0;
  const normalizedCourseId = normalizePositiveInt(courseId) || 0;
  const normalizedProgramId = normalizePositiveInt(programId) || null;
  const normalizedStudyContextId = normalizePositiveInt(studyContextId) || null;
  const normalizedCampusKey = cleanCompactText(campusKey || 'unknown', 40) || 'unknown';
  const normalizedTrackKey = cleanCompactText(trackKey, 20) || null;
  const normalizedStageNumber = normalizeStageNumber(stageNumber, 1);
  return {
    dedupeKey: buildModerationKey(
      'registration-missing-stage-one',
      normalizedUserId || 0,
      normalizedAdmissionId,
      normalizedCampusKey,
      dedupeSuffix || normalizedCourseId || normalizedProgramId || 0
    ),
    sourceKind: 'user',
    sourceId: normalizedUserId || null,
    issueCode: 'missing_stage_one_context',
    severity: 'high',
    title: cleanCompactText(
      title || 'Registration could not resolve a stage 1 study context',
      160
    ),
    summary: cleanCompactText(
      summary || 'Registration did not find a canonical stage 1 study context for the selected cohort and campus.',
      320
    ),
    payload: {
      user_id: normalizedUserId || null,
      program_id: normalizedProgramId,
      admission_id: normalizePositiveInt(admissionId) || null,
      track_key: normalizedTrackKey,
      campus_key: normalizedCampusKey || null,
      stage_number: normalizedStageNumber,
      course_id: normalizePositiveInt(courseId) || null,
      study_context_id: normalizedStudyContextId,
    },
  };
}

function buildRegistrationCourseFallbackIssue({
  userId,
  programId = null,
  admissionId = null,
  trackKey = null,
  campusKey = null,
  stageNumber = 1,
  courseId = null,
  studyContextId = null,
  fallbackSource = 'compatibility',
} = {}) {
  const normalizedUserId = normalizePositiveInt(userId);
  const normalizedCourseId = normalizePositiveInt(courseId) || 0;
  const normalizedCampusKey = cleanCompactText(campusKey || 'unknown', 40) || 'unknown';
  return {
    dedupeKey: buildModerationKey(
      'registration-course-fallback',
      normalizedUserId || 0,
      normalizePositiveInt(admissionId) || 0,
      normalizedCourseId,
      normalizedCampusKey
    ),
    sourceKind: 'user',
    sourceId: normalizedUserId || null,
    issueCode: 'registration_course_fallback',
    severity: 'medium',
    title: 'Registration used compatibility course fallback',
    summary: 'Registration resolved only a legacy course scope and had to continue without a canonical study context.',
    payload: {
      user_id: normalizedUserId || null,
      program_id: normalizePositiveInt(programId) || null,
      admission_id: normalizePositiveInt(admissionId) || null,
      track_key: cleanCompactText(trackKey, 20) || null,
      campus_key: normalizedCampusKey || null,
      stage_number: normalizeStageNumber(stageNumber, 1),
      course_id: normalizePositiveInt(courseId) || null,
      study_context_id: normalizePositiveInt(studyContextId) || null,
      fallback_source: cleanCompactText(fallbackSource, 80) || 'compatibility',
    },
  };
}

function buildContextMissingActiveSemesterIssue(context = {}) {
  const contextId = normalizePositiveInt(context.id || context.study_context_id);
  const offeringCount = Number(context.offering_count || 0) || 0;
  const userCount = Number(context.user_count || 0) || 0;
  return {
    dedupeKey: buildModerationKey('study-context-active-semester', contextId || 0),
    sourceKind: 'study_context',
    sourceId: contextId || null,
    issueCode: 'context_missing_active_semester',
    severity: offeringCount > 0 || userCount > 0 ? 'high' : 'medium',
    title: 'Study context has no active semester',
    summary: 'This study context currently has no active semester even though it already has live data.',
    payload: {
      study_context_id: contextId || null,
      course_id: normalizePositiveInt(context.course_id) || null,
      program_id: normalizePositiveInt(context.program_id) || null,
      admission_id: normalizePositiveInt(context.admission_id) || null,
      track_key: cleanCompactText(context.track_key, 20) || null,
      campus_key: cleanCompactText(context.campus_key, 20) || null,
      stage_number: normalizeStageNumber(context.stage || context.stage_number, 1),
      semester_count: Number(context.semester_count || 0) || 0,
      active_semester_count: Number(context.active_semester_count || 0) || 0,
      offering_count: offeringCount,
      user_count: userCount,
    },
  };
}

function buildSharedOfferingMismatchIssue({
  offeringId,
  studyContextId = null,
  courseId = null,
  targetContextIds = [],
} = {}) {
  return {
    dedupeKey: buildModerationKey('shared-offering-mismatch', normalizePositiveInt(offeringId) || 0),
    sourceKind: 'subject_offering',
    sourceId: normalizePositiveInt(offeringId) || null,
    issueCode: 'shared_offering_mismatch',
    severity: 'medium',
    title: 'Shared offering is linked to an incomplete context scope',
    summary: 'A shared offering should be attached to multiple study contexts but currently has only one visible linked context.',
    payload: {
      offering_id: normalizePositiveInt(offeringId) || null,
      study_context_id: normalizePositiveInt(studyContextId) || null,
      course_id: normalizePositiveInt(courseId) || null,
      target_context_ids: Array.isArray(targetContextIds) ? targetContextIds : [],
      is_shared: true,
    },
  };
}

function buildInvalidTeacherTemplateMatchIssue({
  teacherId = null,
  templateId = null,
  offeringId = null,
  subjectCatalogId = null,
  studyContextId = null,
  semesterId = null,
  courseId = null,
  programId = null,
  trackKey = null,
  stageNumber = null,
  campusKey = null,
  hasContexts = null,
  sourceKind = 'subject_offering',
  dedupeSuffix = '',
  title = '',
  summary = '',
} = {}) {
  const normalizedOfferingId = normalizePositiveInt(offeringId);
  const normalizedTemplateId = normalizePositiveInt(templateId);
  const sourceId = normalizedOfferingId || normalizedTemplateId || null;
  const dedupeKey = buildModerationKey(
    'teacher-template-match',
    normalizePositiveInt(teacherId) || 0,
    dedupeSuffix || sourceId || normalizePositiveInt(studyContextId) || 0
  );
  return {
    dedupeKey,
    sourceKind: cleanCompactText(sourceKind, 40) || 'subject_offering',
    sourceId,
    issueCode: 'invalid_teacher_template_match',
    severity: 'medium',
    title: cleanCompactText(
      title || 'Teacher template sync skipped an invalid offering scope',
      160
    ),
    summary: cleanCompactText(
      summary || 'Recurring template sync found an offering without the metadata needed to match teacher template rules.',
      320
    ),
    payload: {
      teacher_id: normalizePositiveInt(teacherId) || null,
      template_id: normalizedTemplateId,
      offering_id: normalizedOfferingId,
      subject_catalog_id: normalizePositiveInt(subjectCatalogId) || null,
      study_context_id: normalizePositiveInt(studyContextId) || null,
      semester_id: normalizePositiveInt(semesterId) || null,
      course_id: normalizePositiveInt(courseId) || null,
      program_id: normalizePositiveInt(programId) || null,
      track_key: cleanCompactText(trackKey, 20) || null,
      stage_number: normalizePositiveInt(stageNumber) || null,
      campus_key: cleanCompactText(campusKey, 20) || null,
      has_contexts: typeof hasContexts === 'boolean' ? hasContexts : null,
    },
  };
}

function buildMissingTargetContextIssue({
  admissionId,
  courseId,
  programId = null,
  trackKey = null,
} = {}) {
  const normalizedAdmissionId = normalizePositiveInt(admissionId) || 0;
  const normalizedCourseId = normalizePositiveInt(courseId) || 0;
  return {
    dedupeKey: buildModerationKey('course-migration', normalizedAdmissionId, normalizedCourseId),
    sourceKind: 'course_migration',
    sourceId: normalizedCourseId || null,
    issueCode: 'missing_target_context',
    severity: 'high',
    title: 'Missing target study context for migration',
    summary: 'Could not resolve a study context for the selected course during cohort migration.',
    payload: {
      admission_id: normalizePositiveInt(admissionId) || null,
      course_id: normalizePositiveInt(courseId) || null,
      program_id: normalizePositiveInt(programId) || null,
      track_key: cleanCompactText(trackKey, 20) || null,
    },
  };
}

function buildFailedPromotionTargetIssue({
  userId = null,
  admissionId = null,
  programId = null,
  trackKey = null,
  courseId = null,
  studyContextId = null,
  campusKey = null,
  stageNumber = null,
  missingPlacement = false,
} = {}) {
  const normalizedUserId = normalizePositiveInt(userId) || 0;
  const normalizedStudyContextId = normalizePositiveInt(studyContextId) || null;
  const normalizedAdmissionId = normalizePositiveInt(admissionId) || 0;
  return {
    dedupeKey: buildModerationKey(
      'promotion-target',
      normalizedAdmissionId,
      normalizedUserId,
      missingPlacement ? 'missing-placement' : (normalizedStudyContextId || 0)
    ),
    sourceKind: 'user',
    sourceId: normalizedUserId || null,
    issueCode: 'failed_promotion_target',
    severity: 'high',
    title: missingPlacement
      ? 'Promotion skipped user without canonical study context'
      : 'Promotion could not resolve next study context',
    summary: missingPlacement
      ? 'Promotion could not continue because the user has no canonical study context placement.'
      : 'Promotion failed to find or create the next-stage study context for this user.',
    payload: {
      user_id: normalizedUserId || null,
      admission_id: normalizePositiveInt(admissionId) || null,
      program_id: normalizePositiveInt(programId) || null,
      track_key: cleanCompactText(trackKey, 20) || null,
      course_id: normalizePositiveInt(courseId) || null,
      study_context_id: normalizedStudyContextId,
      campus_key: cleanCompactText(campusKey, 20) || null,
      stage_number: normalizePositiveInt(stageNumber) || null,
    },
  };
}

function normalizePositiveInt(value) {
  const normalized = Number(value || 0);
  return Number.isInteger(normalized) && normalized > 0 ? normalized : null;
}

function normalizeLegacyBooleanFlag(value, fallback = false) {
  if (value === null || typeof value === 'undefined' || value === '') {
    return fallback === true;
  }
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 't', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'f', 'no', 'off'].includes(normalized)) return false;
  return fallback === true;
}

function isLegacySchemaCompatibilityError(err) {
  return Boolean(err && (err.code === '42P01' || err.code === '42703'));
}

function normalizeLegacyActiveFlagSql(columnName, fallback = '1') {
  return `COALESCE(LOWER(TRIM(CAST(${columnName} AS TEXT))), '${fallback}') IN ('1', 'true', 't', 'yes', 'on')`;
}

async function getLegacyCourseActiveSemester(store, courseId) {
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedCourseId || !store || typeof store.get !== 'function') {
    return null;
  }
  const row = await store.get(
    `
      SELECT id, title, start_date, weeks_count, is_active, is_archived
      FROM semesters
      WHERE course_id = ?
        AND ${normalizeLegacyActiveFlagSql('is_active', '0')}
      ORDER BY id DESC
      LIMIT 1
    `,
    [normalizedCourseId]
  );
  return row || null;
}

async function listLegacyCourseSemesters(store, {
  courseId,
  activeOnly = false,
} = {}) {
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedCourseId || !store || typeof store.all !== 'function') {
    return [];
  }
  const where = ['course_id = ?'];
  const params = [normalizedCourseId];
  if (activeOnly === true) {
    where.push(normalizeLegacyActiveFlagSql('is_active', '0'));
  }
  const rows = await store.all(
    `
      SELECT id, title, start_date, weeks_count, is_active, is_archived, course_id
      FROM semesters
      WHERE ${where.join(' AND ')}
      ORDER BY start_date DESC, id DESC
    `,
    params
  );
  return Array.isArray(rows) ? rows : [];
}

async function getLegacyCourseSubject(store, {
  subjectId,
  courseId,
  includeHidden = false,
} = {}) {
  const normalizedSubjectId = normalizePositiveInt(subjectId);
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedSubjectId || !normalizedCourseId || !store || typeof store.get !== 'function') {
    return null;
  }
  try {
    const row = await store.get(
      `
        SELECT
          s.*,
          s.course_id AS owner_course_id,
          scb.course_id AS bound_course_id,
          COALESCE(cat.name, s.name) AS catalog_name
        FROM subject_course_bindings scb
        JOIN subjects s ON s.id = scb.subject_id
        LEFT JOIN subject_catalog cat ON cat.id = s.catalog_id
        WHERE s.id = ?
          AND scb.course_id = ?
          ${includeHidden ? '' : `AND ${normalizeLegacyActiveFlagSql('s.visible', '1')}`}
        LIMIT 1
      `,
      [normalizedSubjectId, normalizedCourseId]
    );
    return row || null;
  } catch (err) {
    if (!isLegacySchemaCompatibilityError(err)) {
      throw err;
    }
    const row = await store.get(
      `
        SELECT
          *,
          course_id AS owner_course_id,
          course_id AS bound_course_id,
          name AS catalog_name
        FROM subjects
        WHERE id = ?
          AND course_id = ?
          ${includeHidden ? '' : `AND ${normalizeLegacyActiveFlagSql('visible', '1')}`}
        LIMIT 1
      `,
      [normalizedSubjectId, normalizedCourseId]
    );
    return row || null;
  }
}

async function listLegacyCourseSubjects(store, {
  courseId,
  includeHidden = false,
} = {}) {
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedCourseId || !store || typeof store.all !== 'function') {
    return [];
  }
  try {
    const rows = await store.all(
      `
        SELECT
          s.*,
          s.course_id AS owner_course_id,
          scb.course_id AS bound_course_id,
          COALESCE(cat.name, s.name) AS catalog_name
        FROM subject_course_bindings scb
        JOIN subjects s ON s.id = scb.subject_id
        LEFT JOIN subject_catalog cat ON cat.id = s.catalog_id
        WHERE scb.course_id = ?
          ${includeHidden ? '' : `AND ${normalizeLegacyActiveFlagSql('s.visible', '1')}`}
        ORDER BY s.name ASC, s.id ASC
      `,
      [normalizedCourseId]
    );
    return Array.isArray(rows) ? rows : [];
  } catch (err) {
    if (!isLegacySchemaCompatibilityError(err)) {
      throw err;
    }
    const rows = await store.all(
      `
        SELECT
          *,
          course_id AS owner_course_id,
          course_id AS bound_course_id,
          name AS catalog_name
        FROM subjects
        WHERE course_id = ?
          ${includeHidden ? '' : `AND ${normalizeLegacyActiveFlagSql('visible', '1')}`}
        ORDER BY name ASC, id ASC
      `,
      [normalizedCourseId]
    );
    return Array.isArray(rows) ? rows : [];
  }
}

async function listLegacyStudentGroupRows(store, {
  studentId = null,
  courseId = null,
  subjectId = null,
  includeHidden = false,
} = {}) {
  const normalizedStudentId = normalizePositiveInt(studentId);
  const normalizedCourseId = normalizePositiveInt(courseId);
  const normalizedSubjectId = normalizePositiveInt(subjectId);
  if (!normalizedStudentId || !store || typeof store.all !== 'function') {
    return [];
  }
  const params = [normalizedStudentId];
  const visibilityClause = includeHidden ? '' : `AND ${normalizeLegacyActiveFlagSql('s.visible', '1')}`;
  const subjectClause = normalizedSubjectId ? 'AND sg.subject_id = ?' : '';
  if (normalizedSubjectId) {
    params.push(normalizedSubjectId);
  }
  if (normalizedCourseId) {
    params.push(normalizedCourseId);
    try {
      const rows = await store.all(
        `
          SELECT
            sg.student_id,
            sg.subject_id,
            sg.group_number,
            s.name AS subject_name,
            COALESCE(s.group_count, 1) AS group_count,
            s.show_in_teamwork,
            s.course_id AS owner_course_id,
            scb.course_id AS bound_course_id,
            c.name AS course_name
          FROM student_groups sg
          JOIN subjects s ON s.id = sg.subject_id
          JOIN subject_course_bindings scb ON scb.subject_id = s.id
          LEFT JOIN courses c ON c.id = s.course_id
          WHERE sg.student_id = ?
            ${subjectClause}
            AND scb.course_id = ?
            ${visibilityClause}
          ORDER BY s.name ASC, sg.subject_id ASC, sg.group_number ASC
        `,
        params
      );
      return Array.isArray(rows) ? rows : [];
    } catch (err) {
      if (!isLegacySchemaCompatibilityError(err)) {
        throw err;
      }
      const fallbackRows = await store.all(
        `
          SELECT
            sg.student_id,
            sg.subject_id,
            sg.group_number,
            s.name AS subject_name,
            COALESCE(s.group_count, 1) AS group_count,
            s.show_in_teamwork,
            s.course_id AS owner_course_id,
            s.course_id AS bound_course_id,
            c.name AS course_name
          FROM student_groups sg
          JOIN subjects s ON s.id = sg.subject_id
          LEFT JOIN courses c ON c.id = s.course_id
          WHERE sg.student_id = ?
            ${subjectClause}
            AND s.course_id = ?
            ${visibilityClause}
          ORDER BY s.name ASC, sg.subject_id ASC, sg.group_number ASC
        `,
        params
      );
      return Array.isArray(fallbackRows) ? fallbackRows : [];
    }
  }
  const rows = await store.all(
    `
      SELECT
        sg.student_id,
        sg.subject_id,
        sg.group_number,
        s.name AS subject_name,
        COALESCE(s.group_count, 1) AS group_count,
        s.show_in_teamwork,
        s.course_id AS owner_course_id,
        s.course_id AS bound_course_id,
        c.name AS course_name
      FROM student_groups sg
      JOIN subjects s ON s.id = sg.subject_id
      LEFT JOIN courses c ON c.id = s.course_id
      WHERE sg.student_id = ?
        ${subjectClause}
        ${visibilityClause}
      ORDER BY s.course_id ASC, s.name ASC, sg.subject_id ASC, sg.group_number ASC
    `,
    params
  );
  return Array.isArray(rows) ? rows : [];
}

async function listLegacySubjectStudentRows(store, {
  subjectId,
  courseId = null,
  groupNumbers = [],
  userIds = [],
  activeOnly = false,
} = {}) {
  const normalizedSubjectId = normalizePositiveInt(subjectId);
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedSubjectId || !store || typeof store.all !== 'function') {
    return [];
  }
  const normalizedGroupNumbers = Array.from(new Set(
    (Array.isArray(groupNumbers) ? groupNumbers : [groupNumbers])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const normalizedUserIds = Array.from(new Set(
    (Array.isArray(userIds) ? userIds : [userIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const where = ['sg.subject_id = ?'];
  const params = [normalizedSubjectId];
  if (normalizedCourseId) {
    where.push('u.course_id = ?');
    params.push(normalizedCourseId);
  }
  if (normalizedGroupNumbers.length) {
    where.push('sg.group_number = ANY(?::int[])');
    params.push(normalizedGroupNumbers);
  }
  if (normalizedUserIds.length) {
    where.push('u.id = ANY(?::int[])');
    params.push(normalizedUserIds);
  }
  if (activeOnly === true) {
    where.push(normalizeLegacyActiveFlagSql('u.is_active', '1'));
  }
  const rows = await store.all(
    `
      SELECT DISTINCT u.id, u.full_name, sg.group_number
      FROM student_groups sg
      JOIN users u ON u.id = sg.student_id
      WHERE ${where.join('\n        AND ')}
      ORDER BY sg.group_number ASC, u.full_name ASC
    `,
    params
  );
  return Array.isArray(rows) ? rows : [];
}

async function getLegacyStudentSubjectGroup(store, {
  subjectId,
  studentId,
  activeOnly = false,
} = {}) {
  const normalizedSubjectId = normalizePositiveInt(subjectId);
  const normalizedStudentId = normalizePositiveInt(studentId);
  if (!normalizedSubjectId || !normalizedStudentId || !store || typeof store.get !== 'function') {
    return null;
  }
  const row = await store.get(
    `
      SELECT sg.group_number
      FROM student_groups sg
      JOIN users u ON u.id = sg.student_id
      WHERE sg.subject_id = ?
        AND sg.student_id = ?
        ${activeOnly === true ? `AND ${normalizeLegacyActiveFlagSql('u.is_active', '1')}` : ''}
      LIMIT 1
    `,
    [normalizedSubjectId, normalizedStudentId]
  );
  return row || null;
}

async function getLegacyCourseUser(store, {
  userId,
  courseId,
  activeOnly = false,
} = {}) {
  const normalizedUserId = normalizePositiveInt(userId);
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedUserId || !normalizedCourseId || !store || typeof store.get !== 'function') {
    return null;
  }
  const params = [normalizedUserId, normalizedCourseId];
  const row = await store.get(
    `
      SELECT u.*
      FROM users u
      WHERE u.id = ?
        AND u.course_id = ?
        ${activeOnly === true ? `AND ${normalizeLegacyActiveFlagSql('u.is_active', '1')}` : ''}
      LIMIT 1
    `,
    params
  );
  return row || null;
}

async function listLegacyCourseUsers(store, {
  courseId,
  userIds = [],
  excludeRoles = [],
  activeOnly = false,
} = {}) {
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedCourseId || !store || typeof store.all !== 'function') {
    return [];
  }
  const normalizedUserIds = Array.from(new Set(
    (Array.isArray(userIds) ? userIds : [userIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const normalizedExcludeRoles = Array.from(new Set(
    (Array.isArray(excludeRoles) ? excludeRoles : [excludeRoles])
      .map((value) => cleanCompactText(value, 32).toLowerCase())
      .filter(Boolean)
  ));
  const where = ['u.course_id = ?'];
  const params = [normalizedCourseId];
  if (normalizedUserIds.length) {
    where.push('u.id = ANY(?::int[])');
    params.push(normalizedUserIds);
  }
  if (normalizedExcludeRoles.length) {
    where.push("NOT (LOWER(TRIM(COALESCE(u.role, ''))) = ANY(?::text[]))");
    params.push(normalizedExcludeRoles);
  }
  if (activeOnly === true) {
    where.push(normalizeLegacyActiveFlagSql('u.is_active', '1'));
  }
  const rows = await store.all(
    `
      SELECT u.*
      FROM users u
      WHERE ${where.join(' AND ')}
      ORDER BY u.full_name ASC, u.id ASC
    `,
    params
  );
  return Array.isArray(rows) ? rows : [];
}

async function listLegacyCourseSupportRequests(store, {
  courseId,
  limit = 40,
} = {}) {
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedCourseId || !store || typeof store.all !== 'function') {
    return [];
  }
  const safeLimit = Math.min(Math.max(Number(limit) || 40, 1), 120);
  const rows = await store.all(
    `
      SELECT sr.*, u.full_name AS user_name
      FROM support_requests sr
      JOIN users u ON u.id = sr.user_id
      WHERE sr.course_id = ?
      ORDER BY sr.updated_at DESC, sr.created_at DESC
      LIMIT ${safeLimit}
    `,
    [normalizedCourseId]
  );
  return Array.isArray(rows) ? rows : [];
}

async function getLegacyCourseSupportRequestThread(store, {
  requestId,
  courseId,
} = {}) {
  const normalizedRequestId = normalizePositiveInt(requestId);
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedRequestId || !store || typeof store.get !== 'function') {
    return null;
  }
  const params = [normalizedRequestId];
  const where = ['sr.id = ?'];
  if (normalizedCourseId) {
    where.push('sr.course_id = ?');
    params.push(normalizedCourseId);
  }
  const row = await store.get(
    `
      SELECT
        sr.*,
        u.full_name AS user_name,
        resolver.full_name AS resolved_by_name
      FROM support_requests sr
      JOIN users u ON u.id = sr.user_id
      LEFT JOIN users resolver ON resolver.id = sr.resolved_by
      WHERE ${where.join(' AND ')}
      LIMIT 1
    `,
    params
  );
  return row || null;
}

async function getLegacyCourseDependencyCounts(store, courseId) {
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedCourseId || !store || typeof store.get !== 'function') {
    return { users: 0, subjects: 0, semesters: 0 };
  }
  const [userRow, subjectRow, semesterRow] = await Promise.all([
    store.get('SELECT COUNT(*) AS count FROM users WHERE course_id = ?', [normalizedCourseId]),
    store.get('SELECT COUNT(*) AS count FROM subjects WHERE course_id = ?', [normalizedCourseId]),
    store.get('SELECT COUNT(*) AS count FROM semesters WHERE course_id = ?', [normalizedCourseId]),
  ]);
  return {
    users: Number(userRow && (userRow.count ?? userRow.cnt) || 0),
    subjects: Number(subjectRow && (subjectRow.count ?? subjectRow.cnt) || 0),
    semesters: Number(semesterRow && (semesterRow.count ?? semesterRow.cnt) || 0),
  };
}

async function writeLegacySubjectVisibility(store, {
  admissionId,
  subjectId,
  isVisible = true,
  mode = 'upsert',
} = {}) {
  const normalizedAdmissionId = normalizePositiveInt(admissionId);
  const normalizedSubjectId = normalizePositiveInt(subjectId);
  if (!normalizedAdmissionId || !normalizedSubjectId || !store || typeof store.run !== 'function') {
    return false;
  }
  if (String(mode || '').trim().toLowerCase() === 'delete') {
    await store.run(
      'DELETE FROM subject_visibility_by_admission WHERE admission_id = ? AND subject_id = ?',
      [normalizedAdmissionId, normalizedSubjectId]
    );
    return true;
  }
  await store.run(
    `
      INSERT INTO subject_visibility_by_admission
        (admission_id, subject_id, is_visible, created_at, updated_at)
      VALUES (?, ?, ?, NOW(), NOW())
      ON CONFLICT (admission_id, subject_id)
      DO UPDATE SET
        is_visible = EXCLUDED.is_visible,
        updated_at = NOW()
    `,
    [normalizedAdmissionId, normalizedSubjectId, isVisible === true || Number(isVisible) === 1]
  );
  return true;
}

async function copyLegacySubjectVisibility(store, {
  sourceAdmissionId,
  targetAdmissionId,
} = {}) {
  const normalizedSourceAdmissionId = normalizePositiveInt(sourceAdmissionId);
  const normalizedTargetAdmissionId = normalizePositiveInt(targetAdmissionId);
  if (!normalizedSourceAdmissionId || !normalizedTargetAdmissionId || !store || typeof store.run !== 'function') {
    return false;
  }
  await store.run(
    `
      INSERT INTO subject_visibility_by_admission
        (admission_id, subject_id, is_visible, created_at, updated_at)
      SELECT ?, sva.subject_id, sva.is_visible, NOW(), NOW()
      FROM subject_visibility_by_admission sva
      WHERE sva.admission_id = ?
      ON CONFLICT (admission_id, subject_id)
      DO UPDATE SET
        is_visible = EXCLUDED.is_visible,
        updated_at = NOW()
    `,
    [normalizedTargetAdmissionId, normalizedSourceAdmissionId]
  );
  return true;
}

async function copyLegacySubjectVisibilityForCourse(store, {
  sourceAdmissionId,
  targetAdmissionId,
  courseId,
} = {}) {
  const normalizedSourceAdmissionId = normalizePositiveInt(sourceAdmissionId);
  const normalizedTargetAdmissionId = normalizePositiveInt(targetAdmissionId);
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedSourceAdmissionId || !normalizedTargetAdmissionId || !normalizedCourseId || !store || typeof store.run !== 'function') {
    return false;
  }
  await store.run(
    `
      DELETE FROM subject_visibility_by_admission
      WHERE admission_id = ?
        AND subject_id IN (
          SELECT scb.subject_id
          FROM subject_course_bindings scb
          WHERE scb.course_id = ?
        )
    `,
    [normalizedTargetAdmissionId, normalizedCourseId]
  );
  await store.run(
    `
      INSERT INTO subject_visibility_by_admission
        (admission_id, subject_id, is_visible, created_at, updated_at)
      SELECT
        ?,
        sva.subject_id,
        sva.is_visible,
        NOW(),
        NOW()
      FROM subject_visibility_by_admission sva
      JOIN subject_course_bindings scb ON scb.subject_id = sva.subject_id
      JOIN subjects s ON s.id = scb.subject_id
      WHERE sva.admission_id = ?
        AND scb.course_id = ?
        AND COALESCE(LOWER(TRIM(CAST(s.visible AS TEXT))), '1') IN ('1', 'true', 't')
      ON CONFLICT (admission_id, subject_id)
      DO UPDATE SET
        is_visible = EXCLUDED.is_visible,
        updated_at = NOW()
    `,
    [normalizedTargetAdmissionId, normalizedSourceAdmissionId, normalizedCourseId]
  );
  return true;
}

async function mirrorLegacySubjectVisibilityByAdmissions(store, {
  sourceSubjectId,
  targetSubjectId,
  admissionIds,
} = {}) {
  const normalizedSourceSubjectId = normalizePositiveInt(sourceSubjectId);
  const normalizedTargetSubjectId = normalizePositiveInt(targetSubjectId);
  const normalizedAdmissionIds = Array.from(new Set(
    (Array.isArray(admissionIds) ? admissionIds : [admissionIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  if (!normalizedSourceSubjectId || !normalizedTargetSubjectId || !normalizedAdmissionIds.length || !store || typeof store.all !== 'function' || typeof store.run !== 'function') {
    return 0;
  }
  const visibilityRows = await store.all(
    `
      SELECT admission_id, is_visible
      FROM subject_visibility_by_admission
      WHERE subject_id = ?
        AND admission_id = ANY(?::int[])
    `,
    [normalizedSourceSubjectId, normalizedAdmissionIds]
  );
  const rows = Array.isArray(visibilityRows) ? visibilityRows : [];
  const visibilityMap = new Map();
  rows.forEach((row) => {
    const admissionId = normalizePositiveInt(row && row.admission_id);
    if (!admissionId) return;
    visibilityMap.set(admissionId, row.is_visible === true || Number(row.is_visible) === 1);
  });
  let touched = 0;
  for (const admissionId of normalizedAdmissionIds) {
    if (visibilityMap.has(admissionId)) {
      await writeLegacySubjectVisibility(store, {
        admissionId,
        subjectId: normalizedTargetSubjectId,
        isVisible: visibilityMap.get(admissionId),
      });
    } else {
      await writeLegacySubjectVisibility(store, {
        admissionId,
        subjectId: normalizedTargetSubjectId,
        mode: 'delete',
      });
    }
    touched += 1;
  }
  return touched;
}

async function listLegacyRegistrationPathwayRows(store) {
  if (!store || typeof store.all !== 'function') {
    return [];
  }
  const rows = await store.all(
    `
      SELECT
        p.id AS program_id,
        p.track_key,
        p.code AS program_code,
        p.name AS program_name,
        p.sort_order,
        a.id AS admission_id,
        a.admission_year,
        a.label AS admission_label,
        pac.course_id
      FROM study_programs p
      JOIN program_admissions a ON a.program_id = p.id
      JOIN program_admission_courses pac ON pac.admission_id = a.id
      WHERE p.is_active = true
        AND a.is_active = true
        AND pac.is_visible = true
      ORDER BY
        p.track_key ASC,
        COALESCE(p.sort_order, 100) ASC,
        p.name ASC,
        a.admission_year DESC,
        pac.course_id ASC
    `
  );
  return Array.isArray(rows) ? rows : [];
}

async function listLegacyAdmissionCourseRows(store, {
  admissionId = null,
  admissionIds = [],
  courseId = null,
  courseIds = [],
  programId = null,
  trackKey = '',
  visibleOnly = false,
  activeOnly = false,
} = {}) {
  if (!store || typeof store.all !== 'function') {
    return [];
  }
  const normalizedAdmissionId = normalizePositiveInt(admissionId);
  const normalizedAdmissionIds = Array.from(new Set(
    (Array.isArray(admissionIds) ? admissionIds : [admissionIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const normalizedCourseId = normalizePositiveInt(courseId);
  const normalizedCourseIds = Array.from(new Set(
    (Array.isArray(courseIds) ? courseIds : [courseIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const normalizedProgramId = normalizePositiveInt(programId);
  const normalizedTrackKey = ['bachelor', 'master', 'teacher'].includes(String(trackKey || '').trim().toLowerCase())
    ? String(trackKey || '').trim().toLowerCase()
    : '';
  const where = [];
  const params = [];
  if (normalizedAdmissionId) {
    where.push('pac.admission_id = ?');
    params.push(normalizedAdmissionId);
  } else if (normalizedAdmissionIds.length) {
    where.push('pac.admission_id = ANY(?::int[])');
    params.push(normalizedAdmissionIds);
  }
  if (normalizedProgramId) {
    where.push('a.program_id = ?');
    params.push(normalizedProgramId);
  }
  if (normalizedCourseId) {
    where.push('pac.course_id = ?');
    params.push(normalizedCourseId);
  } else if (normalizedCourseIds.length) {
    where.push('pac.course_id = ANY(?::int[])');
    params.push(normalizedCourseIds);
  }
  if (normalizedTrackKey) {
    where.push('p.track_key = ?');
    params.push(normalizedTrackKey);
  }
  if (visibleOnly) {
    where.push('pac.is_visible = true');
  }
  if (activeOnly) {
    where.push('a.is_active = true');
    where.push('p.is_active = true');
  }
  const rows = await store.all(
    `
      SELECT
        pac.admission_id,
        pac.course_id,
        pac.is_visible,
        a.program_id,
        a.admission_year,
        a.label AS admission_label,
        a.is_active AS admission_is_active,
        p.track_key,
        p.code AS program_code,
        p.name AS program_name,
        p.is_active AS program_is_active,
        c.name AS course_name,
        COALESCE(c.location, 'kyiv') AS course_location,
        c.is_teacher_course
      FROM program_admission_courses pac
      JOIN program_admissions a ON a.id = pac.admission_id
      JOIN study_programs p ON p.id = a.program_id
      JOIN courses c ON c.id = pac.course_id
      ${where.length ? `WHERE ${where.join('\n        AND ')}` : ''}
      ORDER BY
        a.admission_year DESC,
        pac.admission_id ASC,
        CASE COALESCE(c.location, 'kyiv')
          WHEN 'kyiv' THEN 0
          WHEN 'munich' THEN 1
          ELSE 2
        END,
        c.id ASC
    `,
    params
  );
  return Array.isArray(rows) ? rows : [];
}

async function listLegacyAdmissionSubjectVisibilityRows(store, {
  admissionId,
  admissionIds = [],
  courseId = null,
  subjectId = null,
} = {}) {
  const normalizedAdmissionId = normalizePositiveInt(admissionId);
  const normalizedAdmissionIds = Array.from(new Set(
    (Array.isArray(admissionIds) ? admissionIds : [admissionIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const normalizedCourseId = normalizePositiveInt(courseId);
  const normalizedSubjectId = normalizePositiveInt(subjectId);
  if ((!normalizedAdmissionId && !normalizedAdmissionIds.length) || !store || typeof store.all !== 'function') {
    return [];
  }
  const params = [];
  const where = [];
  if (normalizedAdmissionId) {
    where.push('sva.admission_id = ?');
    params.push(normalizedAdmissionId);
  } else {
    where.push('sva.admission_id = ANY(?::int[])');
    params.push(normalizedAdmissionIds);
  }
  const courseJoin = normalizedCourseId ? 'JOIN subject_course_bindings scb ON scb.subject_id = sva.subject_id' : '';
  if (normalizedCourseId) {
    where.push('scb.course_id = ?');
    params.push(normalizedCourseId);
  }
  if (normalizedSubjectId) {
    where.push('sva.subject_id = ?');
    params.push(normalizedSubjectId);
  }
  if (normalizedCourseId) {
    // handled above
  }
  const rows = await store.all(
    `
      SELECT sva.admission_id, sva.subject_id, sva.is_visible
      FROM subject_visibility_by_admission sva
      ${courseJoin}
      WHERE ${where.join('\n        AND ')}
    `,
    params
  );
  return Array.isArray(rows) ? rows : [];
}

async function listLegacyAdmissionCourseStats(store, admissionIds = []) {
  const normalizedAdmissionIds = Array.from(new Set(
    (Array.isArray(admissionIds) ? admissionIds : [admissionIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  if (!normalizedAdmissionIds.length || !store || typeof store.all !== 'function') {
    return [];
  }
  const rows = await store.all(
    `
      SELECT
        pac.admission_id,
        COUNT(*) FILTER (
          WHERE COALESCE(LOWER(TRIM(CAST(pac.is_visible AS TEXT))), '1') IN ('1', 'true', 't', 'yes', 'on', '')
        )::int AS visible_count,
        COUNT(*)::int AS total_count
      FROM program_admission_courses pac
      WHERE pac.admission_id = ANY(?::int[])
      GROUP BY pac.admission_id
    `,
    [normalizedAdmissionIds]
  );
  return Array.isArray(rows) ? rows : [];
}

async function listLegacyAdmissionSubjectVisibilityStats(store, {
  admissionIds = [],
  courseId,
} = {}) {
  const normalizedAdmissionIds = Array.from(new Set(
    (Array.isArray(admissionIds) ? admissionIds : [admissionIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedAdmissionIds.length || !normalizedCourseId || !store || typeof store.all !== 'function') {
    return [];
  }
  const rows = await store.all(
    `
      SELECT
        a.id AS admission_id,
        COUNT(*) FILTER (
          WHERE COALESCE(LOWER(TRIM(CAST(s.visible AS TEXT))), '1') IN ('1', 'true', 't', 'yes', 'on', '')
        )::int AS total_count,
        COUNT(*) FILTER (
          WHERE COALESCE(LOWER(TRIM(CAST(s.visible AS TEXT))), '1') IN ('1', 'true', 't', 'yes', 'on', '')
            AND COALESCE(LOWER(TRIM(CAST(sva.is_visible AS TEXT))), '1') IN ('1', 'true', 't', 'yes', 'on', '')
        )::int AS visible_count,
        COUNT(*) FILTER (
          WHERE COALESCE(LOWER(TRIM(CAST(s.visible AS TEXT))), '1') IN ('1', 'true', 't', 'yes', 'on', '')
            AND sva.subject_id IS NOT NULL
        )::int AS override_count
      FROM program_admissions a
      LEFT JOIN subject_course_bindings scb ON scb.course_id = ?
      LEFT JOIN subjects s ON s.id = scb.subject_id
      LEFT JOIN subject_visibility_by_admission sva
        ON sva.admission_id = a.id
       AND sva.subject_id = s.id
      WHERE a.id = ANY(?::int[])
      GROUP BY a.id
    `,
    [normalizedCourseId, normalizedAdmissionIds]
  );
  return Array.isArray(rows) ? rows : [];
}

async function listLegacyAdmissionIdsForSubjectIds(store, subjectIds = []) {
  const normalizedSubjectIds = Array.from(new Set(
    (Array.isArray(subjectIds) ? subjectIds : [subjectIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  if (!normalizedSubjectIds.length || !store || typeof store.all !== 'function') {
    return [];
  }
  const rows = await store.all(
    `
      SELECT DISTINCT pac.admission_id
      FROM subject_course_bindings scb
      JOIN program_admission_courses pac ON pac.course_id = scb.course_id
      WHERE scb.subject_id = ANY(?::int[])
    `,
    [normalizedSubjectIds]
  );
  return Array.isArray(rows) ? rows : [];
}

async function listLegacyTeacherCatalogRows(store) {
  if (!store || typeof store.all !== 'function') {
    return [];
  }
  try {
    const rows = await store.all(
      `
        SELECT
          s.id,
          s.name,
          s.group_count,
          s.is_general,
          s.course_id,
          s.course_id AS owner_course_id,
          COALESCE(binding_scope.course_labels, owner_course.name) AS course_name,
          COALESCE(pathways.pathway_labels, '') AS pathway_labels
        FROM subjects s
        JOIN courses owner_course ON owner_course.id = s.course_id
        LEFT JOIN LATERAL (
          SELECT STRING_AGG(DISTINCT c.name, ', ' ORDER BY c.name) AS course_labels
          FROM subject_course_bindings scb
          JOIN courses c ON c.id = scb.course_id
          WHERE scb.subject_id = s.id
        ) binding_scope ON true
        LEFT JOIN LATERAL (
          SELECT STRING_AGG(
            DISTINCT (
              CASE
                WHEN COALESCE(p.code, '') <> '' THEN p.code || ' '
                ELSE ''
              END
              || p.name
              || ' '
              || a.admission_year::text
            ),
            ', '
          ) AS pathway_labels
          FROM subject_course_bindings scb
          JOIN program_admission_courses pac ON pac.course_id = scb.course_id
          JOIN program_admissions a ON a.id = pac.admission_id
          JOIN study_programs p ON p.id = a.program_id
          WHERE scb.subject_id = s.id
            AND pac.is_visible = true
            AND a.is_active = true
            AND p.is_active = true
        ) pathways ON true
        WHERE s.visible = 1
          AND EXISTS (
            SELECT 1
            FROM subject_course_bindings scb
            JOIN semesters sem ON sem.course_id = scb.course_id
            WHERE scb.subject_id = s.id
              AND sem.is_active = 1
          )
        ORDER BY s.name ASC, s.id ASC
      `
    );
    return Array.isArray(rows) ? rows : [];
  } catch (err) {
    if (!(err && (err.code === '42P01' || err.code === '42703'))) {
      throw err;
    }
    const fallbackRows = await store.all(
      `
        SELECT s.id, s.name, s.group_count, s.is_general, s.course_id, s.course_id AS owner_course_id, c.name AS course_name
        FROM subjects s
        JOIN courses c ON c.id = s.course_id
        WHERE s.visible = 1
          AND EXISTS (
            SELECT 1
            FROM semesters sem
            WHERE sem.course_id = s.course_id AND sem.is_active = 1
          )
        ORDER BY c.id, s.name
      `
    );
    return Array.isArray(fallbackRows) ? fallbackRows : [];
  }
}

async function upsertLegacyAdmissionCourseMappings(store, {
  admissionId,
  mappings = [],
} = {}) {
  const normalizedAdmissionId = normalizePositiveInt(admissionId);
  const normalizedMappings = (Array.isArray(mappings) ? mappings : [])
    .map((mapping) => ({
      course_id: normalizePositiveInt(mapping && mapping.course_id),
      is_visible: normalizeLegacyBooleanFlag(mapping && mapping.is_visible, false),
    }))
    .filter((mapping) => mapping.course_id);
  if (!normalizedAdmissionId || !normalizedMappings.length || !store || typeof store.run !== 'function') {
    return 0;
  }
  let writes = 0;
  for (const mapping of normalizedMappings) {
    await store.run(
      `
        INSERT INTO program_admission_courses
          (admission_id, course_id, is_visible, created_at, updated_at)
        VALUES (?, ?, ?, NOW(), NOW())
        ON CONFLICT (admission_id, course_id)
        DO UPDATE SET
          is_visible = EXCLUDED.is_visible,
          updated_at = NOW()
      `,
      [normalizedAdmissionId, mapping.course_id, mapping.is_visible]
    );
    writes += 1;
  }
  return writes;
}

async function copyLegacyAdmissionCourseMappings(store, {
  sourceAdmissionId,
  targetAdmissionId,
  courseIds = [],
} = {}) {
  const normalizedSourceAdmissionId = normalizePositiveInt(sourceAdmissionId);
  const normalizedTargetAdmissionId = normalizePositiveInt(targetAdmissionId);
  const normalizedCourseIds = Array.from(new Set(
    (Array.isArray(courseIds) ? courseIds : [courseIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  if (
    !normalizedSourceAdmissionId
    || !normalizedTargetAdmissionId
    || !normalizedCourseIds.length
    || !store
    || typeof store.run !== 'function'
  ) {
    return 0;
  }
  await store.run(
    `
      INSERT INTO program_admission_courses
        (admission_id, course_id, is_visible, created_at, updated_at)
      SELECT
        ?,
        c.id,
        COALESCE(src.is_visible, false),
        NOW(),
        NOW()
      FROM courses c
      LEFT JOIN program_admission_courses src
        ON src.course_id = c.id
       AND src.admission_id = ?
      WHERE c.id = ANY(?::int[])
      ON CONFLICT (admission_id, course_id)
      DO UPDATE SET
        is_visible = EXCLUDED.is_visible,
        updated_at = NOW()
    `,
    [normalizedTargetAdmissionId, normalizedSourceAdmissionId, normalizedCourseIds]
  );
  return normalizedCourseIds.length;
}

async function resolveUserAcademicPlacement({
  userOrId,
  lang = 'uk',
  loadUserById,
  loadStudyContextById,
  ensureStudyContextForLegacyPlacement,
  loadCourseById,
  buildStudyContextLabel,
  inferLegacyCourseOrdinal,
  sanitizeText,
} = {}) {
  const normalizedLang = lang === 'en' ? 'en' : 'uk';
  const userRow = typeof userOrId === 'object' && userOrId
    ? userOrId
    : (typeof loadUserById === 'function'
      ? await loadUserById(normalizePositiveInt(userOrId))
      : null);
  if (!userRow) {
    return null;
  }

  const studyContextId = normalizePositiveInt(userRow.study_context_id);
  const placement = {
    user_id: normalizePositiveInt(userRow.id),
    study_context_id: studyContextId || null,
    course_id: normalizePositiveInt(userRow.course_id) || null,
    admission_id: normalizePositiveInt(userRow.admission_id) || null,
    program_id: normalizePositiveInt(userRow.study_program_id) || null,
    track_key: normalizeTrackKey(userRow.study_track, 'bachelor'),
    campus_key: '',
    stage: 1,
    course_name: '',
    program_code: '',
    program_name: '',
    admission_year: null,
    cohort_label: '',
    context_label: '',
  };

  const decorateWithContext = (context) => ({
    ...placement,
    study_context_id: normalizePositiveInt(context && context.id) || null,
    course_id: normalizePositiveInt(context && context.course_id) || placement.course_id,
    admission_id: normalizePositiveInt(context && context.admission_id) || placement.admission_id,
    program_id: normalizePositiveInt(context && context.program_id) || placement.program_id,
    track_key: normalizeTrackKey(context && context.track_key, placement.track_key),
    campus_key: normalizeCampusKey(context && (context.campus_key || context.course_location), 'kyiv'),
    stage: normalizeStageNumber(context && (context.stage || context.stage_number), 1),
    course_name: cleanCompactText(context && context.course_name, 140),
    program_code: cleanCompactText(context && context.program_code, 40),
    program_name: cleanCompactText(context && context.program_name, 140),
    admission_year: normalizePositiveInt(context && context.admission_year) || null,
    cohort_label: cleanCompactText(context && context.cohort_label, 160),
    context_label: typeof buildStudyContextLabel === 'function'
      ? buildStudyContextLabel(context, normalizedLang)
      : '',
    raw_context: context,
  });

  if (studyContextId && typeof loadStudyContextById === 'function') {
    const context = await loadStudyContextById(studyContextId);
    if (context) {
      return decorateWithContext(context);
    }
  }

  if (
    placement.course_id
    && placement.admission_id
    && typeof ensureStudyContextForLegacyPlacement === 'function'
    && typeof loadStudyContextById === 'function'
  ) {
    const ensuredContextId = await ensureStudyContextForLegacyPlacement({
      courseId: placement.course_id,
      admissionId: placement.admission_id,
      programId: placement.program_id,
      trackKey: placement.track_key,
    });
    if (ensuredContextId) {
      const context = await loadStudyContextById(ensuredContextId);
      if (context) {
        return decorateWithContext(context);
      }
    }
  }

  const course = placement.course_id && typeof loadCourseById === 'function'
    ? await loadCourseById(placement.course_id)
    : null;
  placement.campus_key = normalizeCampusKey(course && course.location, 'kyiv');
  placement.stage = normalizeStageNumber(
    typeof inferLegacyCourseOrdinal === 'function'
      ? inferLegacyCourseOrdinal(course && course.name)
      : null,
    1
  );
  placement.course_name = typeof sanitizeText === 'function'
    ? sanitizeText(course && course.name, 140)
    : cleanCompactText(course && course.name, 140);
  placement.context_label = typeof buildStudyContextLabel === 'function'
    ? buildStudyContextLabel({
      program_code: placement.program_code,
      program_name: placement.program_name || (placement.track_key === 'teacher' ? 'Teacher Track' : ''),
      admission_year: placement.admission_year,
      campus_key: placement.campus_key,
      stage: placement.stage,
      track_key: placement.track_key,
    }, normalizedLang)
    : '';
  return placement;
}

async function assignUserStudyContext({
  store,
  userId,
  studyContextId,
  fallback = {},
  loadStudyContextById,
} = {}) {
  const normalizedUserId = normalizePositiveInt(userId);
  if (!normalizedUserId || !store || typeof store.run !== 'function') {
    return null;
  }
  const normalizedStudyContextId = normalizePositiveInt(studyContextId);
  const context = normalizedStudyContextId && typeof loadStudyContextById === 'function'
    ? await loadStudyContextById(normalizedStudyContextId)
    : null;
  const nextCourseId = context
    ? (normalizePositiveInt(context.course_id) || null)
    : (normalizePositiveInt(fallback.courseId) || null);
  const nextTrackKey = context
    ? normalizeTrackKey(context.track_key, '')
    : normalizeTrackKey(fallback.trackKey, '');
  const nextProgramId = context
    ? (normalizePositiveInt(context.program_id) || null)
    : (normalizePositiveInt(fallback.programId) || null);
  const nextAdmissionId = context
    ? (normalizePositiveInt(context.admission_id) || normalizePositiveInt(fallback.admissionId) || null)
    : (normalizePositiveInt(fallback.admissionId) || null);

  await store.run(
    `
      UPDATE users
      SET
        study_context_id = ?,
        course_id = ?,
        study_track = ?,
        study_program_id = ?,
        admission_id = ?
      WHERE id = ?
    `,
    [
      normalizedStudyContextId || null,
      nextCourseId,
      nextTrackKey || null,
      nextProgramId,
      nextAdmissionId,
      normalizedUserId,
    ]
  );

  if (!normalizedStudyContextId || !context) {
    return null;
  }
  return context;
}

async function ensureNextStudyContextForPromotion({
  placement,
  store,
  loadCourses,
  courseMatchesRegistrationTrack,
  inferLegacyCourseOrdinal,
  ensureStudyContextForLegacyPlacement,
  applyProgramPresetToStudyContext,
} = {}) {
  if (!placement || !normalizePositiveInt(placement.admission_id) || !store || typeof store.get !== 'function') {
    return null;
  }
  const nextStage = normalizeStageNumber(Number(placement.stage || 0) + 1, 1);
  const campusKey = normalizeCampusKey(placement.campus_key || 'kyiv', 'kyiv');
  const directMatch = await store.get(
    `
      SELECT sc.id
      FROM study_contexts sc
      JOIN cohorts coh ON coh.id = sc.cohort_id
      WHERE coh.legacy_admission_id = ?
        AND sc.stage_number = ?
        AND sc.campus_key = ?
      ORDER BY sc.id ASC
      LIMIT 1
    `,
    [normalizePositiveInt(placement.admission_id), nextStage, campusKey]
  );
  if (directMatch && directMatch.id) {
    return normalizePositiveInt(directMatch.id);
  }

  const courses = typeof loadCourses === 'function'
    ? await loadCourses()
    : [];
  const candidateCourses = (Array.isArray(courses) ? courses : [])
    .filter((course) => (typeof courseMatchesRegistrationTrack === 'function'
      ? courseMatchesRegistrationTrack(course, placement.track_key)
      : true))
    .filter((course) => normalizeCampusKey(course && course.location, 'kyiv') === campusKey)
    .filter((course) => normalizeStageNumber(
      typeof inferLegacyCourseOrdinal === 'function'
        ? inferLegacyCourseOrdinal(course && course.name)
        : null,
      0
    ) === nextStage);
  if (candidateCourses.length !== 1 || typeof ensureStudyContextForLegacyPlacement !== 'function') {
    return null;
  }

  const ensuredContextId = await ensureStudyContextForLegacyPlacement({
    courseId: candidateCourses[0].id,
    admissionId: placement.admission_id,
    programId: placement.program_id,
    trackKey: placement.track_key,
    preferredCampus: campusKey,
    preferredStage: nextStage,
  });
  if (ensuredContextId && typeof applyProgramPresetToStudyContext === 'function') {
    await applyProgramPresetToStudyContext(ensuredContextId);
  }
  return normalizePositiveInt(ensuredContextId);
}

async function loadProgramPresets(db, programId) {
  const normalizedProgramId = Number(programId || 0);
  if (!Number.isInteger(normalizedProgramId) || normalizedProgramId < 1) {
    return [];
  }
  const rows = await db.all(
    `
      SELECT
        pp.id,
        pp.program_id,
        pp.name,
        pp.is_default,
        pp.is_active,
        pp.source_cohort_id,
        ps.id AS stage_id,
        ps.stage_number,
        ps.label AS stage_label,
        ps.sort_order AS stage_sort_order,
        ps.is_active AS stage_is_active,
        sem.id AS semester_id,
        sem.semester_number,
        sem.title AS semester_title,
        sem.start_date,
        sem.weeks_count,
        sem.is_active AS semester_is_active,
        sem.is_archived,
        sem.sort_order AS semester_sort_order,
        pss.id AS preset_stage_subject_id,
        pss.subject_catalog_id,
        pss.label AS subject_label,
        pss.group_count,
        pss.default_group,
        pss.is_required,
        pss.is_shared,
        pss.sort_order AS subject_sort_order,
        cat.name AS catalog_name,
        link.preset_semester_id AS linked_preset_semester_id
      FROM program_presets pp
      LEFT JOIN program_preset_stages ps
        ON ps.preset_id = pp.id
      LEFT JOIN program_preset_semesters sem
        ON sem.preset_stage_id = ps.id
      LEFT JOIN program_preset_stage_subjects pss
        ON pss.preset_stage_id = ps.id
      LEFT JOIN subject_catalog cat
        ON cat.id = pss.subject_catalog_id
      LEFT JOIN program_preset_stage_subject_semesters link
        ON link.preset_stage_subject_id = pss.id
      WHERE pp.program_id = ?
      ORDER BY
        pp.is_default DESC,
        pp.name ASC,
        ps.stage_number ASC NULLS LAST,
        sem.semester_number ASC NULLS LAST,
        pss.sort_order ASC NULLS LAST,
        pss.id ASC NULLS LAST
    `,
    [normalizedProgramId]
  );

  const presetMap = new Map();
  for (const row of rows || []) {
    const presetId = Number(row.id || 0);
    if (!presetId) continue;
    if (!presetMap.has(presetId)) {
      presetMap.set(presetId, {
        id: presetId,
        program_id: normalizedProgramId,
        name: cleanCompactText(row.name, 140),
        is_default: row.is_default === true || Number(row.is_default) === 1,
        is_active: row.is_active === true || Number(row.is_active) === 1,
        source_cohort_id: Number(row.source_cohort_id || 0) || null,
        stages: [],
      });
    }
    const preset = presetMap.get(presetId);
    const stageId = Number(row.stage_id || 0);
    let stage = null;
    if (stageId) {
      stage = preset.stages.find((item) => Number(item.id || 0) === stageId) || null;
      if (!stage) {
        stage = {
          id: stageId,
          stage_number: normalizeStageNumber(row.stage_number, preset.stages.length + 1),
          label: cleanCompactText(row.stage_label, 120) || cleanCompactText(buildStageLabel(row.stage_number, 'bachelor', 'uk'), 120),
          sort_order: Number(row.stage_sort_order || row.stage_number || 0),
          is_active: row.stage_is_active === true || Number(row.stage_is_active) === 1,
          semesters: [],
          subjects: [],
        };
        preset.stages.push(stage);
      }
    }

    if (stage) {
      const semesterId = Number(row.semester_id || 0);
      if (semesterId && !stage.semesters.find((item) => Number(item.id || 0) === semesterId)) {
        stage.semesters.push({
          id: semesterId,
          semester_number: Number(row.semester_number || 0) || null,
          title: cleanCompactText(row.semester_title, 120),
          start_date: cleanCompactText(row.start_date, 32),
          weeks_count: Number(row.weeks_count || 0) || null,
          is_active: row.semester_is_active === true || Number(row.semester_is_active) === 1,
          is_archived: row.is_archived === true || Number(row.is_archived) === 1,
          sort_order: Number(row.semester_sort_order || row.semester_number || 0),
        });
      }

      const subjectId = Number(row.preset_stage_subject_id || 0);
      if (subjectId) {
        let subject = stage.subjects.find((item) => Number(item.id || 0) === subjectId) || null;
        if (!subject) {
          subject = {
            id: subjectId,
            subject_catalog_id: Number(row.subject_catalog_id || 0) || null,
            catalog_name: cleanCompactText(row.catalog_name, 140),
            label: cleanCompactText(row.subject_label, 140),
            group_count: Math.max(1, Number(row.group_count || 1)),
            default_group: Math.max(1, Number(row.default_group || 1)),
            is_required: !(row.is_required === false || Number(row.is_required) === 0),
            is_shared: row.is_shared === true || Number(row.is_shared) === 1,
            sort_order: Number(row.subject_sort_order || 0),
            semester_ids: [],
          };
          stage.subjects.push(subject);
        }
        const linkedSemesterId = Number(row.linked_preset_semester_id || 0);
        if (linkedSemesterId && !subject.semester_ids.includes(linkedSemesterId)) {
          subject.semester_ids.push(linkedSemesterId);
        }
      }
    }
  }

  return Array.from(presetMap.values()).map((preset) => ({
    ...preset,
    stages: preset.stages
      .sort((a, b) => Number(a.stage_number || 0) - Number(b.stage_number || 0))
      .map((stage) => ({
        ...stage,
        semesters: stage.semesters.sort((a, b) => Number(a.semester_number || 0) - Number(b.semester_number || 0)),
        subjects: stage.subjects.sort((a, b) => {
          if (Number(a.sort_order || 0) !== Number(b.sort_order || 0)) {
            return Number(a.sort_order || 0) - Number(b.sort_order || 0);
          }
          return String(a.label || a.catalog_name || '').localeCompare(String(b.label || b.catalog_name || ''));
        }),
      })),
  }));
}

async function ensureDefaultPreset(client, {
  programId,
  programName,
  trackKey,
  presetName,
  sourceCohortId = null,
  stageCount = null,
}) {
  const normalizedProgramId = Number(programId || 0);
  if (!Number.isInteger(normalizedProgramId) || normalizedProgramId < 1) {
    return null;
  }
  const normalizedTrack = normalizeTrackKey(trackKey, 'bachelor');
  const finalPresetName = cleanCompactText(
    presetName,
    140
  ) || `${cleanCompactText(programName, 120) || `Program ${normalizedProgramId}`} default preset`;
  const insertedPreset = await client.query(
    `
      INSERT INTO program_presets
        (program_id, name, is_default, is_active, source_cohort_id, created_at, updated_at)
      VALUES ($1, $2, TRUE, TRUE, $3, NOW(), NOW())
      ON CONFLICT (program_id, name)
      DO UPDATE SET
        is_default = EXCLUDED.is_default,
        is_active = EXCLUDED.is_active,
        source_cohort_id = COALESCE(program_presets.source_cohort_id, EXCLUDED.source_cohort_id),
        updated_at = NOW()
      RETURNING id
    `,
    [normalizedProgramId, finalPresetName, Number(sourceCohortId || 0) || null]
  );
  const presetId = Number(insertedPreset.rows && insertedPreset.rows[0] ? insertedPreset.rows[0].id : 0) || null;
  if (!presetId) {
    return null;
  }

  await client.query(
    `
      UPDATE program_presets
      SET
        is_default = CASE WHEN id = $2 THEN TRUE ELSE FALSE END,
        updated_at = NOW()
      WHERE program_id = $1
    `,
    [normalizedProgramId, presetId]
  );

  const finalStageCount = normalizeStageCountByTrack(normalizedTrack, stageCount);
  for (let stageNumber = 1; stageNumber <= finalStageCount; stageNumber += 1) {
    await client.query(
      `
        INSERT INTO program_preset_stages
          (preset_id, stage_number, label, sort_order, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, TRUE, NOW(), NOW())
        ON CONFLICT (preset_id, stage_number)
        DO UPDATE SET
          label = EXCLUDED.label,
          sort_order = EXCLUDED.sort_order,
          is_active = TRUE,
          updated_at = NOW()
      `,
      [presetId, stageNumber, buildStageLabel(stageNumber, normalizedTrack, 'uk'), stageNumber]
    );
  }

  await client.query(
    `
      UPDATE program_preset_stages
      SET is_active = CASE WHEN stage_number <= $2 THEN TRUE ELSE FALSE END,
          updated_at = NOW()
      WHERE preset_id = $1
    `,
    [presetId, finalStageCount]
  );

  return presetId;
}

async function buildContextApplyPreview(db, { studyContextId, presetId = null }) {
  const normalizedStudyContextId = Number(studyContextId || 0);
  if (!Number.isInteger(normalizedStudyContextId) || normalizedStudyContextId < 1) {
    return null;
  }
  const context = await db.get(
    `
      SELECT
        sc.id,
        sc.stage_number,
        coh.id AS cohort_id,
        coh.program_id,
        p.track_key
      FROM study_contexts sc
      JOIN cohorts coh ON coh.id = sc.cohort_id
      JOIN study_programs p ON p.id = coh.program_id
      WHERE sc.id = ?
      LIMIT 1
    `,
    [normalizedStudyContextId]
  );
  if (!context) {
    return null;
  }

  let resolvedPresetId = Number(presetId || 0) || null;
  if (!resolvedPresetId) {
    const presetRow = await db.get(
      `
        SELECT id
        FROM program_presets
        WHERE program_id = ?
          AND is_default = true
          AND is_active = true
        ORDER BY id ASC
        LIMIT 1
      `,
      [Number(context.program_id || 0)]
    );
    resolvedPresetId = Number(presetRow && presetRow.id ? presetRow.id : 0) || null;
  }
  if (!resolvedPresetId) {
    return {
      preset_id: null,
      context_id: normalizedStudyContextId,
      stage_number: normalizeStageNumber(context.stage_number, 1),
      create_semesters: 0,
      update_semesters: 0,
      archive_semesters: 0,
      create_offerings: 0,
      update_offerings: 0,
      archive_offerings: 0,
      teacher_assignments: 0,
    };
  }

  const presetStage = await db.get(
    `
      SELECT
        ps.id,
        ps.stage_number,
        ps.label
      FROM program_preset_stages ps
      WHERE ps.preset_id = ?
        AND ps.stage_number = ?
        AND ps.is_active = true
      LIMIT 1
    `,
    [resolvedPresetId, normalizeStageNumber(context.stage_number, 1)]
  );
  if (!presetStage) {
    return {
      preset_id: resolvedPresetId,
      context_id: normalizedStudyContextId,
      stage_number: normalizeStageNumber(context.stage_number, 1),
      create_semesters: 0,
      update_semesters: 0,
      archive_semesters: 0,
      create_offerings: 0,
      update_offerings: 0,
      archive_offerings: 0,
      teacher_assignments: 0,
    };
  }

  const [presetSemesters, currentSemesters, presetSubjects, currentOfferings] = await Promise.all([
    db.all(
      `
        SELECT id, semester_number, title, start_date, weeks_count, is_active, is_archived
        FROM program_preset_semesters
        WHERE preset_stage_id = ?
        ORDER BY semester_number ASC
      `,
      [presetStage.id]
    ),
    db.all(
      `
        SELECT id, semester_number, preset_semester_id, title, start_date, weeks_count, is_active, is_archived
        FROM study_context_semesters
        WHERE study_context_id = ?
        ORDER BY semester_number ASC
      `,
      [normalizedStudyContextId]
    ),
    db.all(
      `
        SELECT id, subject_catalog_id
        FROM program_preset_stage_subjects
        WHERE preset_stage_id = ?
        ORDER BY sort_order ASC, id ASC
      `,
      [presetStage.id]
    ),
    db.all(
      `
        SELECT
          so.id,
          so.preset_stage_subject_id,
          so.subject_catalog_id,
          so.is_active
        FROM subject_offerings so
        JOIN subject_offering_contexts soc
          ON soc.subject_offering_id = so.id
        WHERE soc.study_context_id = ?
      `,
      [normalizedStudyContextId]
    ),
  ]);

  const currentSemesterByPresetId = new Map(
    (currentSemesters || [])
      .filter((row) => Number(row.preset_semester_id || 0) > 0)
      .map((row) => [Number(row.preset_semester_id), row])
  );
  const currentSemesterByNumber = new Map(
    (currentSemesters || []).map((row) => [Number(row.semester_number || 0), row])
  );
  let createSemesters = 0;
  let updateSemesters = 0;
  for (const presetSemester of presetSemesters || []) {
    const existing = currentSemesterByPresetId.get(Number(presetSemester.id || 0))
      || currentSemesterByNumber.get(Number(presetSemester.semester_number || 0))
      || null;
    if (!existing) {
      createSemesters += 1;
    } else {
      updateSemesters += 1;
    }
  }
  const presetSemesterIdSet = new Set((presetSemesters || []).map((row) => Number(row.id || 0)).filter(Boolean));
  const archiveSemesters = (currentSemesters || []).filter((row) => {
    const presetSemesterIdValue = Number(row.preset_semester_id || 0);
    return presetSemesterIdValue > 0 && !presetSemesterIdSet.has(presetSemesterIdValue);
  }).length;

  const currentOfferingByPresetId = new Map(
    (currentOfferings || [])
      .filter((row) => Number(row.preset_stage_subject_id || 0) > 0)
      .map((row) => [Number(row.preset_stage_subject_id), row])
  );
  const currentOfferingByCatalogId = new Map(
    (currentOfferings || [])
      .filter((row) => Number(row.subject_catalog_id || 0) > 0)
      .map((row) => [Number(row.subject_catalog_id), row])
  );
  let createOfferings = 0;
  let updateOfferings = 0;
  for (const presetSubject of presetSubjects || []) {
    const existing = currentOfferingByPresetId.get(Number(presetSubject.id || 0))
      || currentOfferingByCatalogId.get(Number(presetSubject.subject_catalog_id || 0))
      || null;
    if (!existing) {
      createOfferings += 1;
    } else {
      updateOfferings += 1;
    }
  }
  const presetSubjectIdSet = new Set((presetSubjects || []).map((row) => Number(row.id || 0)).filter(Boolean));
  const archiveOfferings = (currentOfferings || []).filter((row) => {
    const presetSubjectIdValue = Number(row.preset_stage_subject_id || 0);
    return presetSubjectIdValue > 0 && !presetSubjectIdSet.has(presetSubjectIdValue);
  }).length;

  return {
    preset_id: resolvedPresetId,
    context_id: normalizedStudyContextId,
    stage_number: normalizeStageNumber(context.stage_number, 1),
    create_semesters: createSemesters,
    update_semesters: updateSemesters,
    archive_semesters: archiveSemesters,
    create_offerings: createOfferings,
    update_offerings: updateOfferings,
    archive_offerings: archiveOfferings,
    teacher_assignments: createOfferings + updateOfferings,
  };
}

async function listAcademicModerationItems(db, { status = 'open', limit = 50 } = {}) {
  const normalizedStatus = ['open', 'reviewing', 'resolved', 'ignored'].includes(String(status || '').trim().toLowerCase())
    ? String(status || '').trim().toLowerCase()
    : 'open';
  const normalizedLimit = Math.max(1, Math.min(Number(limit || 50) || 50, 200));
  const rows = await db.all(
    `
      SELECT
        amq.id,
        amq.source_kind,
        amq.source_id,
        amq.issue_code,
        amq.severity,
        amq.status,
        amq.title,
        amq.summary,
        amq.payload_json,
        amq.created_at,
        amq.updated_at,
        amq.resolved_at,
        amq.resolved_by,
        u.full_name AS resolved_by_name
      FROM academic_moderation_queue amq
      LEFT JOIN users u ON u.id = amq.resolved_by
      WHERE amq.status = ?
      ORDER BY
        CASE amq.severity
          WHEN 'high' THEN 0
          WHEN 'medium' THEN 1
          ELSE 2
        END,
        amq.created_at DESC,
        amq.id DESC
      LIMIT ?
    `,
    [normalizedStatus, normalizedLimit]
  );
  return (rows || []).map((row) => {
    let payload = {};
    try {
      payload = row.payload_json && typeof row.payload_json === 'object'
        ? row.payload_json
        : JSON.parse(String(row.payload_json || '{}'));
    } catch (_) {
      payload = {};
    }
    return {
      id: Number(row.id || 0) || null,
      source_kind: cleanCompactText(row.source_kind, 80),
      source_id: Number(row.source_id || 0) || null,
      issue_code: cleanCompactText(row.issue_code, 80),
      severity: cleanCompactText(row.severity, 20) || 'medium',
      status: cleanCompactText(row.status, 20) || 'open',
      title: cleanCompactText(row.title, 160),
      summary: cleanCompactText(row.summary, 320),
      payload,
      created_at: cleanCompactText(row.created_at, 40),
      updated_at: cleanCompactText(row.updated_at, 40),
      resolved_at: cleanCompactText(row.resolved_at, 40),
      resolved_by: Number(row.resolved_by || 0) || null,
      resolved_by_name: cleanCompactText(row.resolved_by_name, 160),
    };
  });
}

async function resolveAcademicModerationItem({
  db,
  queueId,
  action,
  resolvedBy = null,
  assignedStudyContextId = null,
  assignUserStudyContext = null,
}) {
  const normalizedQueueId = Number(queueId || 0);
  if (!Number.isInteger(normalizedQueueId) || normalizedQueueId < 1) {
    return null;
  }
  const normalizedAction = ['open', 'resolved', 'ignored', 'reviewing'].includes(String(action || '').trim().toLowerCase())
    ? String(action || '').trim().toLowerCase()
    : 'resolved';
  const item = await db.get(
    `
      SELECT id, source_kind, source_id, payload_json
      FROM academic_moderation_queue
      WHERE id = ?
      LIMIT 1
    `,
    [normalizedQueueId]
  );
  if (!item) {
    return null;
  }
  let payload = {};
  try {
    payload = item.payload_json && typeof item.payload_json === 'object'
      ? item.payload_json
      : JSON.parse(String(item.payload_json || '{}'));
  } catch (_) {
    payload = {};
  }
  if (
    normalizedAction === 'resolved'
    && Number(assignedStudyContextId || 0) > 0
    && (
      (String(item.source_kind || '') === 'user' && Number(item.source_id || 0) > 0)
      || Number(payload.user_id || 0) > 0
    )
  ) {
    const targetUserId = Number(item.source_id || 0) > 0 && String(item.source_kind || '') === 'user'
      ? Number(item.source_id || 0)
      : (normalizePositiveInt(payload.user_id) || null);
    if (targetUserId && typeof assignUserStudyContext === 'function') {
      await assignUserStudyContext(targetUserId, Number(assignedStudyContextId));
    }
  }
  await db.run(
    `
      UPDATE academic_moderation_queue
      SET
        status = ?,
        resolved_by = ?,
        resolved_at = CASE
          WHEN ? IN ('resolved', 'ignored') THEN NOW()
          WHEN ? = 'reviewing' THEN resolved_at
          ELSE NULL
        END,
        updated_at = NOW()
      WHERE id = ?
    `,
    [
      normalizedAction,
      normalizedAction === 'open' ? null : (Number(resolvedBy || 0) || null),
      normalizedAction,
      normalizedAction,
      normalizedQueueId,
    ]
  );
  return {
    id: normalizedQueueId,
    status: normalizedAction,
  };
}

module.exports = {
  buildAcademicTrackOrderKey,
  buildContextApplyPreview,
  buildContextMissingActiveSemesterIssue,
  buildFailedPromotionTargetIssue,
  buildInvalidTeacherTemplateMatchIssue,
  buildMissingTargetContextIssue,
  buildModerationKey,
  buildRegistrationCourseFallbackIssue,
  buildRegistrationMissingStageOneIssue,
  buildSharedOfferingMismatchIssue,
  buildStageLabel,
  assignUserStudyContext,
  cleanCompactText,
  copyLegacyAdmissionCourseMappings,
  copyLegacySubjectVisibilityForCourse,
  copyLegacySubjectVisibility,
  ensureNextStudyContextForPromotion,
  ensureDefaultPreset,
  getLegacyCourseActiveSemester,
  getLegacyCourseDependencyCounts,
  getLegacyCourseSubject,
  getLegacyCourseSupportRequestThread,
  getLegacyCourseUser,
  listLegacyAdmissionIdsForSubjectIds,
  listLegacyAdmissionCourseRows,
  listLegacyAdmissionCourseStats,
  listLegacyAdmissionSubjectVisibilityRows,
  listLegacyAdmissionSubjectVisibilityStats,
  listAcademicModerationItems,
  listLegacyCourseSemesters,
  listLegacyStudentGroupRows,
  listLegacySubjectStudentRows,
  listLegacyCourseSubjects,
  listLegacyCourseSupportRequests,
  listLegacyCourseUsers,
  getLegacyStudentSubjectGroup,
  listLegacyRegistrationPathwayRows,
  listLegacyTeacherCatalogRows,
  loadProgramPresets,
  mirrorLegacySubjectVisibilityByAdmissions,
  normalizeCampusKey,
  normalizeStageCountByTrack,
  normalizeStageNumber,
  normalizeTrackKey,
  resolveAdminAcademicScopeState,
  resolveUserAcademicPlacement,
  resolveAcademicModerationItem,
  upsertLegacyAdmissionCourseMappings,
  upsertAcademicModerationItem,
  writeLegacySubjectVisibility,
};
