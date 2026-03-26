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

function buildModerationKey(...parts) {
  return parts
    .map((part) => String(part === null || typeof part === 'undefined' ? '' : part).trim())
    .filter(Boolean)
    .join('::');
}

function normalizePositiveInt(value) {
  const normalized = Number(value || 0);
  return Number.isInteger(normalized) && normalized > 0 ? normalized : null;
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
}) {
  const normalizedQueueId = Number(queueId || 0);
  if (!Number.isInteger(normalizedQueueId) || normalizedQueueId < 1) {
    return null;
  }
  const normalizedAction = ['resolved', 'ignored', 'reviewing'].includes(String(action || '').trim().toLowerCase())
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
  if (
    normalizedAction === 'resolved'
    && String(item.source_kind || '') === 'user'
    && Number(item.source_id || 0) > 0
    && Number(assignedStudyContextId || 0) > 0
  ) {
    await db.run(
      `
        UPDATE users
        SET study_context_id = ?
        WHERE id = ?
      `,
      [Number(assignedStudyContextId), Number(item.source_id)]
    );
  }
  await db.run(
    `
      UPDATE academic_moderation_queue
      SET
        status = ?,
        resolved_by = ?,
        resolved_at = CASE WHEN ? IN ('resolved', 'ignored') THEN NOW() ELSE resolved_at END,
        updated_at = NOW()
      WHERE id = ?
    `,
    [normalizedAction, Number(resolvedBy || 0) || null, normalizedAction, normalizedQueueId]
  );
  return {
    id: normalizedQueueId,
    status: normalizedAction,
  };
}

module.exports = {
  buildContextApplyPreview,
  buildModerationKey,
  buildStageLabel,
  assignUserStudyContext,
  cleanCompactText,
  copyLegacySubjectVisibilityForCourse,
  copyLegacySubjectVisibility,
  ensureDefaultPreset,
  listAcademicModerationItems,
  loadProgramPresets,
  mirrorLegacySubjectVisibilityByAdmissions,
  normalizeCampusKey,
  normalizeStageCountByTrack,
  normalizeStageNumber,
  normalizeTrackKey,
  resolveUserAcademicPlacement,
  resolveAcademicModerationItem,
  writeLegacySubjectVisibility,
};
