const CAMPUS_KEYS = new Set(['kyiv', 'munich']);

const ddl = [
  `
    CREATE TABLE IF NOT EXISTS cohorts (
      id SERIAL PRIMARY KEY,
      program_id INTEGER NOT NULL REFERENCES study_programs(id) ON DELETE CASCADE,
      admission_year INTEGER NOT NULL,
      label TEXT NOT NULL,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      legacy_admission_id INTEGER REFERENCES program_admissions(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(program_id, admission_year),
      UNIQUE(legacy_admission_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS study_contexts (
      id SERIAL PRIMARY KEY,
      cohort_id INTEGER NOT NULL REFERENCES cohorts(id) ON DELETE CASCADE,
      stage_number INTEGER NOT NULL,
      campus_key TEXT NOT NULL,
      label TEXT NOT NULL,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(cohort_id, stage_number, campus_key),
      CHECK (campus_key IN ('kyiv', 'munich'))
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS study_context_course_bindings (
      study_context_id INTEGER NOT NULL REFERENCES study_contexts(id) ON DELETE CASCADE,
      course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      is_primary BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(study_context_id, course_id)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS study_context_course_bindings_course_idx
    ON study_context_course_bindings (course_id, study_context_id)
  `,
  `
    CREATE TABLE IF NOT EXISTS program_presets (
      id SERIAL PRIMARY KEY,
      program_id INTEGER NOT NULL REFERENCES study_programs(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      is_default BOOLEAN NOT NULL DEFAULT FALSE,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      source_cohort_id INTEGER REFERENCES cohorts(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(program_id, name)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS program_preset_stages (
      id SERIAL PRIMARY KEY,
      preset_id INTEGER NOT NULL REFERENCES program_presets(id) ON DELETE CASCADE,
      stage_number INTEGER NOT NULL,
      label TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(preset_id, stage_number)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS program_preset_semesters (
      id SERIAL PRIMARY KEY,
      preset_stage_id INTEGER NOT NULL REFERENCES program_preset_stages(id) ON DELETE CASCADE,
      semester_number INTEGER NOT NULL,
      title TEXT NOT NULL,
      start_date TEXT,
      weeks_count INTEGER,
      is_active BOOLEAN NOT NULL DEFAULT FALSE,
      is_archived BOOLEAN NOT NULL DEFAULT FALSE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(preset_stage_id, semester_number)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS program_preset_stage_subjects (
      id SERIAL PRIMARY KEY,
      preset_stage_id INTEGER NOT NULL REFERENCES program_preset_stages(id) ON DELETE CASCADE,
      subject_catalog_id INTEGER NOT NULL REFERENCES subject_catalog(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      group_count INTEGER NOT NULL DEFAULT 1,
      default_group INTEGER NOT NULL DEFAULT 1,
      is_required BOOLEAN NOT NULL DEFAULT TRUE,
      is_shared BOOLEAN NOT NULL DEFAULT FALSE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(preset_stage_id, subject_catalog_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS program_preset_stage_subject_semesters (
      preset_stage_subject_id INTEGER NOT NULL REFERENCES program_preset_stage_subjects(id) ON DELETE CASCADE,
      preset_semester_id INTEGER NOT NULL REFERENCES program_preset_semesters(id) ON DELETE CASCADE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(preset_stage_subject_id, preset_semester_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS study_context_semesters (
      id SERIAL PRIMARY KEY,
      study_context_id INTEGER NOT NULL REFERENCES study_contexts(id) ON DELETE CASCADE,
      semester_number INTEGER NOT NULL,
      title TEXT NOT NULL,
      start_date TEXT,
      weeks_count INTEGER,
      is_active BOOLEAN NOT NULL DEFAULT FALSE,
      is_archived BOOLEAN NOT NULL DEFAULT FALSE,
      preset_semester_id INTEGER REFERENCES program_preset_semesters(id) ON DELETE SET NULL,
      legacy_semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(study_context_id, semester_number)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS study_context_semesters_legacy_idx
    ON study_context_semesters (legacy_semester_id, study_context_id)
  `,
  `
    CREATE TABLE IF NOT EXISTS subject_offerings (
      id SERIAL PRIMARY KEY,
      dedupe_key TEXT NOT NULL UNIQUE,
      subject_catalog_id INTEGER NOT NULL REFERENCES subject_catalog(id) ON DELETE CASCADE,
      preset_stage_subject_id INTEGER REFERENCES program_preset_stage_subjects(id) ON DELETE SET NULL,
      title TEXT NOT NULL,
      is_shared BOOLEAN NOT NULL DEFAULT FALSE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS subject_offering_contexts (
      subject_offering_id INTEGER NOT NULL REFERENCES subject_offerings(id) ON DELETE CASCADE,
      study_context_id INTEGER NOT NULL REFERENCES study_contexts(id) ON DELETE CASCADE,
      is_primary BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(subject_offering_id, study_context_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS subject_offering_semesters (
      subject_offering_id INTEGER NOT NULL REFERENCES subject_offerings(id) ON DELETE CASCADE,
      study_context_semester_id INTEGER NOT NULL REFERENCES study_context_semesters(id) ON DELETE CASCADE,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(subject_offering_id, study_context_semester_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS teacher_assignment_templates (
      id SERIAL PRIMARY KEY,
      dedupe_key TEXT NOT NULL UNIQUE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      subject_catalog_id INTEGER NOT NULL REFERENCES subject_catalog(id) ON DELETE CASCADE,
      program_id INTEGER REFERENCES study_programs(id) ON DELETE SET NULL,
      track_key TEXT,
      stage_number INTEGER,
      campus_key TEXT,
      preference_order INTEGER NOT NULL DEFAULT 0,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (track_key IS NULL OR track_key IN ('bachelor', 'master', 'teacher')),
      CHECK (campus_key IS NULL OR campus_key IN ('kyiv', 'munich'))
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS teacher_offering_assignments (
      id SERIAL PRIMARY KEY,
      teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      subject_offering_id INTEGER NOT NULL REFERENCES subject_offerings(id) ON DELETE CASCADE,
      template_id INTEGER REFERENCES teacher_assignment_templates(id) ON DELETE SET NULL,
      group_number INTEGER,
      is_primary BOOLEAN NOT NULL DEFAULT FALSE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(teacher_id, subject_offering_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_moderation_queue (
      id SERIAL PRIMARY KEY,
      dedupe_key TEXT NOT NULL UNIQUE,
      source_kind TEXT NOT NULL,
      source_id INTEGER,
      issue_code TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'medium',
      status TEXT NOT NULL DEFAULT 'open',
      title TEXT NOT NULL,
      summary TEXT NOT NULL,
      payload_json JSONB NOT NULL DEFAULT '{}'::jsonb,
      resolved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      resolved_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (severity IN ('low', 'medium', 'high')),
      CHECK (status IN ('open', 'reviewing', 'resolved', 'ignored'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS academic_moderation_queue_status_idx
    ON academic_moderation_queue (status, source_kind, issue_code, created_at DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS program_presets_program_idx
    ON program_presets (program_id, is_default, name)
  `,
  `
    CREATE INDEX IF NOT EXISTS program_preset_stages_preset_idx
    ON program_preset_stages (preset_id, stage_number)
  `,
  `
    CREATE INDEX IF NOT EXISTS program_preset_semesters_stage_idx
    ON program_preset_semesters (preset_stage_id, semester_number)
  `,
  `
    CREATE INDEX IF NOT EXISTS program_preset_stage_subjects_stage_idx
    ON program_preset_stage_subjects (preset_stage_id, subject_catalog_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS study_contexts_cohort_stage_idx
    ON study_contexts (cohort_id, stage_number, campus_key)
  `,
  `
    CREATE INDEX IF NOT EXISTS study_context_semesters_context_idx
    ON study_context_semesters (study_context_id, semester_number, is_active)
  `,
  `
    CREATE INDEX IF NOT EXISTS subject_offerings_catalog_idx
    ON subject_offerings (subject_catalog_id, is_shared, is_active)
  `,
  `
    CREATE INDEX IF NOT EXISTS subject_offering_contexts_context_idx
    ON subject_offering_contexts (study_context_id, subject_offering_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS subject_offering_semesters_context_idx
    ON subject_offering_semesters (study_context_semester_id, subject_offering_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS teacher_assignment_templates_user_idx
    ON teacher_assignment_templates (user_id, subject_catalog_id, is_active)
  `,
  `
    CREATE INDEX IF NOT EXISTS teacher_offering_assignments_teacher_idx
    ON teacher_offering_assignments (teacher_id, subject_offering_id)
  `,
];

function normalizeCompactText(rawValue) {
  return String(rawValue || '')
    .replace(/\s+/g, ' ')
    .trim();
}

function normalizeCampusKey(rawValue) {
  const normalized = normalizeCompactText(rawValue).toLowerCase();
  if (CAMPUS_KEYS.has(normalized)) {
    return normalized;
  }
  if (normalized.includes('munich') || normalized.includes('\u043c\u044e\u043d\u0445') || normalized === 'm' || normalized === 'mu') {
    return 'munich';
  }
  return 'kyiv';
}

function extractStageNumber(rawValue) {
  const normalized = normalizeCompactText(rawValue).toLowerCase();
  if (!normalized) return null;
  const patterns = [
    /(?:^|[\s(/,.-])(\d{1,2})\s*(?:\u043a\u0443\u0440\u0441|course)\b/u,
    /\b(?:\u043a\u0443\u0440\u0441|course)\s*(\d{1,2})\b/u,
    /^(\d{1,2})\b/u,
  ];
  for (const pattern of patterns) {
    const match = normalized.match(pattern);
    if (!match) continue;
    const value = Number(match[1]);
    if (Number.isInteger(value) && value > 0) {
      return value;
    }
  }
  return null;
}

function buildLabel(programName, admissionYear, stageNumber, campusKey) {
  return `${normalizeCompactText(programName) || 'Program'} ${admissionYear} stage ${stageNumber} ${campusKey}`;
}

function buildModerationKey(...parts) {
  return parts
    .map((part) => normalizeCompactText(part))
    .filter(Boolean)
    .join('::')
    .toLowerCase();
}

async function enqueueModeration(client, {
  dedupeKey,
  sourceKind,
  sourceId = null,
  issueCode,
  severity = 'medium',
  title,
  summary,
  payload = {},
}) {
  await client.query(
    `
      INSERT INTO academic_moderation_queue
        (dedupe_key, source_kind, source_id, issue_code, severity, status, title, summary, payload_json, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, 'open', $6, $7, $8::jsonb, NOW(), NOW())
      ON CONFLICT (dedupe_key)
      DO UPDATE SET
        source_kind = EXCLUDED.source_kind,
        source_id = EXCLUDED.source_id,
        issue_code = EXCLUDED.issue_code,
        severity = EXCLUDED.severity,
        title = EXCLUDED.title,
        summary = EXCLUDED.summary,
        payload_json = EXCLUDED.payload_json,
        updated_at = NOW()
    `,
    [
      dedupeKey,
      sourceKind,
      sourceId,
      issueCode,
      severity,
      title,
      summary,
      JSON.stringify(payload || {}),
    ]
  );
}

async function up(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const statement of ddl) {
      await client.query(statement);
    }
    await client.query(
      `
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS study_context_id INTEGER REFERENCES study_contexts(id) ON DELETE SET NULL
      `
    );

    const [
      programRows,
      admissionRows,
      semesterRows,
      subjectRows,
      subjectCatalogRows,
    ] = await Promise.all([
      client.query(
        `
          SELECT id, track_key, code, name, sort_order, is_active
          FROM study_programs
          ORDER BY
            CASE track_key
              WHEN 'bachelor' THEN 0
              WHEN 'master' THEN 1
              WHEN 'teacher' THEN 2
              ELSE 3
            END,
            COALESCE(sort_order, 100),
            id
        `
      ),
      client.query(
        `
          SELECT id, program_id, admission_year, label, is_active
          FROM program_admissions
          ORDER BY program_id, admission_year DESC, id DESC
        `
      ),
      client.query(
        `
          SELECT id, name, is_teacher_course, location
          FROM courses
          ORDER BY id
        `
      ),
      client.query(
        `
          SELECT id, course_id, title, start_date, weeks_count, is_active, is_archived
          FROM semesters
          ORDER BY course_id, COALESCE(NULLIF(start_date, ''), '9999-12-31'), id
        `
      ),
      client.query(
        `
          SELECT id, name, group_count, default_group, is_required, is_general, course_id, catalog_id, is_shared
          FROM subjects
          ORDER BY id
        `
      ),
      client.query(
        `
          SELECT id, name, normalized_name
          FROM subject_catalog
          ORDER BY id
        `
      ),
      client.query(
        `
          SELECT subject_id, course_id
          FROM subject_course_bindings
          ORDER BY subject_id, course_id
        `
      ),
    ]);

    const programsById = new Map((programRows.rows || []).map((row) => [Number(row.id), row]));
    const subjectCatalogByNormalizedName = new Map(
      (subjectCatalogRows.rows || []).map((row) => [normalizeCompactText(row.normalized_name || row.name).toLowerCase(), row])
    );

    for (const row of subjectRows.rows || []) {
      const subjectId = Number(row.id);
      const normalizedName = normalizeCompactText(row.name).toLowerCase();
      if (!subjectId || !normalizedName || row.catalog_id) {
        continue;
      }
      let catalogRow = subjectCatalogByNormalizedName.get(normalizedName) || null;
      if (!catalogRow) {
        const inserted = await client.query(
          `
            INSERT INTO subject_catalog (name, normalized_name, created_at, updated_at)
            VALUES ($1, $2, NOW(), NOW())
            ON CONFLICT (normalized_name)
            DO UPDATE SET
              name = EXCLUDED.name,
              updated_at = NOW()
            RETURNING id, name, normalized_name
          `,
          [normalizeCompactText(row.name), normalizedName]
        );
        catalogRow = inserted.rows && inserted.rows[0] ? inserted.rows[0] : null;
        if (catalogRow) {
          subjectCatalogByNormalizedName.set(normalizedName, catalogRow);
        }
      }
      if (catalogRow) {
        await client.query('UPDATE subjects SET catalog_id = $1 WHERE id = $2', [Number(catalogRow.id), subjectId]);
      }
    }

    const refreshedSubjectRows = await client.query(
      `
        SELECT id, name, group_count, default_group, is_required, is_general, course_id, catalog_id, is_shared
        FROM subjects
        ORDER BY id
      `
    );
    const cohortIdByAdmissionId = new Map();
    for (const admission of admissionRows.rows || []) {
      const admissionId = Number(admission.id);
      const programId = Number(admission.program_id);
      if (!admissionId || !programId || !programsById.has(programId)) {
        continue;
      }
      const inserted = await client.query(
        `
          INSERT INTO cohorts
            (program_id, admission_year, label, is_active, legacy_admission_id, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
          ON CONFLICT (program_id, admission_year)
          DO UPDATE SET
            label = EXCLUDED.label,
            is_active = EXCLUDED.is_active,
            legacy_admission_id = COALESCE(cohorts.legacy_admission_id, EXCLUDED.legacy_admission_id),
            updated_at = NOW()
          RETURNING id
        `,
        [
          programId,
          Number(admission.admission_year),
          normalizeCompactText(admission.label) || `Cohort ${admission.admission_year}`,
          admission.is_active === true || Number(admission.is_active) === 1,
          admissionId,
        ]
      );
      const cohortId = Number(inserted.rows && inserted.rows[0] ? inserted.rows[0].id : 0);
      if (cohortId) {
        cohortIdByAdmissionId.set(admissionId, cohortId);
      }
    }

    const semesterRowsByCourseId = new Map();
    for (const semester of semesterRows.rows || []) {
      const courseId = Number(semester.course_id);
      if (!courseId) continue;
      if (!semesterRowsByCourseId.has(courseId)) {
        semesterRowsByCourseId.set(courseId, []);
      }
      semesterRowsByCourseId.get(courseId).push(semester);
    }

    const contextByKey = new Map();
    const contextCourseIdsByContextId = new Map();
    const contextMetaById = new Map();

    const courseAdmissionRows = await client.query(
      `
        SELECT
          pac.admission_id,
          pac.course_id,
          a.program_id,
          a.admission_year,
          p.name AS program_name,
          c.name AS course_name,
          c.location AS course_location,
          c.is_teacher_course
        FROM program_admission_courses pac
        JOIN program_admissions a ON a.id = pac.admission_id
        JOIN study_programs p ON p.id = a.program_id
        JOIN courses c ON c.id = pac.course_id
        WHERE pac.is_visible = TRUE
        ORDER BY a.program_id, a.admission_year DESC, pac.course_id ASC
      `
    );

    for (const row of courseAdmissionRows.rows || []) {
      const admissionId = Number(row.admission_id);
      const courseId = Number(row.course_id);
      const programId = Number(row.program_id);
      const cohortId = cohortIdByAdmissionId.get(admissionId);
      if (!admissionId || !courseId || !programId || !cohortId) {
        continue;
      }

      const stageNumber = extractStageNumber(row.course_name);
      const campusKey = normalizeCampusKey(row.course_location || row.course_name);
      if (!stageNumber) {
        await enqueueModeration(client, {
          dedupeKey: buildModerationKey('study-context', 'stage-not-resolved', admissionId, courseId),
          sourceKind: 'study_context',
          sourceId: courseId,
          issueCode: 'stage_not_resolved',
          severity: 'high',
          title: 'Legacy course stage could not be resolved',
          summary: `Could not derive a stage number for ${normalizeCompactText(row.course_name) || `course ${courseId}`}.`,
          payload: {
            admission_id: admissionId,
            program_id: programId,
            course_id: courseId,
            course_name: row.course_name,
            campus_key: campusKey,
          },
        });
        continue;
      }

      const contextKey = `${cohortId}:${stageNumber}:${campusKey}`;
      let contextId = contextByKey.get(contextKey);
      if (!contextId) {
        const label = buildLabel(row.program_name, Number(row.admission_year), stageNumber, campusKey);
        const inserted = await client.query(
          `
            INSERT INTO study_contexts
              (cohort_id, stage_number, campus_key, label, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, TRUE, NOW(), NOW())
            ON CONFLICT (cohort_id, stage_number, campus_key)
            DO UPDATE SET
              label = EXCLUDED.label,
              is_active = EXCLUDED.is_active,
              updated_at = NOW()
            RETURNING id
          `,
          [cohortId, stageNumber, campusKey, label]
        );
        contextId = Number(inserted.rows && inserted.rows[0] ? inserted.rows[0].id : 0);
        if (!contextId) {
          continue;
        }
        contextByKey.set(contextKey, contextId);
        contextMetaById.set(contextId, {
          cohort_id: cohortId,
          program_id: programId,
          admission_id: admissionId,
          stage_number: stageNumber,
          campus_key: campusKey,
        });
      }

      if (!contextCourseIdsByContextId.has(contextId)) {
        contextCourseIdsByContextId.set(contextId, []);
      }
      contextCourseIdsByContextId.get(contextId).push(courseId);
      await client.query(
        `
          INSERT INTO study_context_course_bindings
            (study_context_id, course_id, is_primary, created_at, updated_at)
          VALUES ($1, $2, $3, NOW(), NOW())
          ON CONFLICT (study_context_id, course_id)
          DO UPDATE SET
            is_primary = EXCLUDED.is_primary OR study_context_course_bindings.is_primary,
            updated_at = NOW()
        `,
        [contextId, courseId, (contextCourseIdsByContextId.get(contextId) || []).length === 1]
      );
    }

    for (const [contextId, contextCourseIds] of contextCourseIdsByContextId.entries()) {
      const uniqueCourseIds = Array.from(new Set((contextCourseIds || []).map((value) => Number(value)).filter((value) => Number.isInteger(value) && value > 0)));
      if (!uniqueCourseIds.length) {
        continue;
      }
      const primaryCourseId = uniqueCourseIds[0];
      const semRows = semesterRowsByCourseId.get(primaryCourseId) || [];
      for (let index = 0; index < semRows.length; index += 1) {
        const sem = semRows[index];
        const semesterNumber = index + 1;
        const inserted = await client.query(
          `
            INSERT INTO study_context_semesters
              (study_context_id, semester_number, title, start_date, weeks_count, is_active, is_archived, legacy_semester_id, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
            ON CONFLICT (study_context_id, semester_number)
            DO UPDATE SET
              title = EXCLUDED.title,
              start_date = EXCLUDED.start_date,
              weeks_count = EXCLUDED.weeks_count,
              is_active = EXCLUDED.is_active,
              is_archived = EXCLUDED.is_archived,
              legacy_semester_id = COALESCE(study_context_semesters.legacy_semester_id, EXCLUDED.legacy_semester_id),
              updated_at = NOW()
            RETURNING id
          `,
          [
            contextId,
            semesterNumber,
            normalizeCompactText(sem.title) || `Semester ${semesterNumber}`,
            sem.start_date || null,
            Number.isFinite(Number(sem.weeks_count)) ? Number(sem.weeks_count) : null,
            sem.is_active === true || Number(sem.is_active) === 1,
            sem.is_archived === true || Number(sem.is_archived) === 1,
            Number(sem.id),
          ]
        );
        const contextSemesterId = Number(inserted.rows && inserted.rows[0] ? inserted.rows[0].id : 0);
        if (!contextSemesterId) continue;
      }
    }

    const presetByProgramId = new Map();
    for (const program of programRows.rows || []) {
      const programId = Number(program.id);
      if (!programId) continue;
      const sourceCohortRow = (admissionRows.rows || []).find((row) => Number(row.program_id) === programId) || null;
      const sourceCohortId = sourceCohortRow ? cohortIdByAdmissionId.get(Number(sourceCohortRow.id)) || null : null;
      const presetName = `${normalizeCompactText(program.name) || `Program ${programId}`} legacy preset`;
      const inserted = await client.query(
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
        [programId, presetName, sourceCohortId]
      );
      const presetId = Number(inserted.rows && inserted.rows[0] ? inserted.rows[0].id : 0);
      if (!presetId) continue;
      presetByProgramId.set(programId, presetId);
    }

    const stageByPresetAndStage = new Map();
    const contextSemesterRows = await client.query(
      `
        SELECT
          id,
          study_context_id,
          semester_number,
          title,
          start_date,
          weeks_count,
          is_active,
          is_archived
        FROM study_context_semesters
        ORDER BY study_context_id, semester_number
      `
    );
    const contextSemesterRowsByContext = new Map();
    for (const row of contextSemesterRows.rows || []) {
      if (!contextSemesterRowsByContext.has(Number(row.study_context_id))) {
        contextSemesterRowsByContext.set(Number(row.study_context_id), []);
      }
      contextSemesterRowsByContext.get(Number(row.study_context_id)).push(row);
    }

    const stageSourceContextByPresetStage = new Map();
    for (const [contextId, meta] of contextMetaById.entries()) {
      const presetId = presetByProgramId.get(meta.program_id);
      if (!presetId) continue;
      const stageKey = `${presetId}:${meta.stage_number}`;
      let presetStageId = stageByPresetAndStage.get(stageKey);
      if (!presetStageId) {
        const inserted = await client.query(
          `
            INSERT INTO program_preset_stages
              (preset_id, stage_number, label, sort_order, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, TRUE, NOW(), NOW())
            ON CONFLICT (preset_id, stage_number)
            DO UPDATE SET
              label = EXCLUDED.label,
              sort_order = EXCLUDED.sort_order,
              is_active = EXCLUDED.is_active,
              updated_at = NOW()
            RETURNING id
          `,
          [presetId, meta.stage_number, `Stage ${meta.stage_number}`, meta.stage_number]
        );
        presetStageId = Number(inserted.rows && inserted.rows[0] ? inserted.rows[0].id : 0);
        if (presetStageId) {
          stageByPresetAndStage.set(stageKey, presetStageId);
        }
      }
      if (!presetStageId) continue;
      if (!stageSourceContextByPresetStage.has(stageKey)) {
        stageSourceContextByPresetStage.set(stageKey, contextId);
      }

      const sourceSemesters = contextSemesterRowsByContext.get(Number(contextId)) || [];
      for (let index = 0; index < sourceSemesters.length; index += 1) {
        const sem = sourceSemesters[index];
        const presetSemesterInsert = await client.query(
          `
            INSERT INTO program_preset_semesters
              (preset_stage_id, semester_number, title, start_date, weeks_count, is_active, is_archived, sort_order, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
            ON CONFLICT (preset_stage_id, semester_number)
            DO UPDATE SET
              title = EXCLUDED.title,
              start_date = EXCLUDED.start_date,
              weeks_count = EXCLUDED.weeks_count,
              is_active = EXCLUDED.is_active,
              is_archived = EXCLUDED.is_archived,
              sort_order = EXCLUDED.sort_order,
              updated_at = NOW()
            RETURNING id
          `,
          [
            presetStageId,
            Number(sem.semester_number),
            normalizeCompactText(sem.title) || `Semester ${sem.semester_number}`,
            sem.start_date || null,
            Number.isFinite(Number(sem.weeks_count)) ? Number(sem.weeks_count) : null,
            sem.is_active === true || Number(sem.is_active) === 1,
            sem.is_archived === true || Number(sem.is_archived) === 1,
            Number(sem.semester_number),
          ]
        );
        const presetSemesterId = Number(presetSemesterInsert.rows && presetSemesterInsert.rows[0] ? presetSemesterInsert.rows[0].id : 0);
        if (presetSemesterId) {
          await client.query(
            `
              UPDATE study_context_semesters
              SET preset_semester_id = COALESCE(preset_semester_id, $1), updated_at = NOW()
              WHERE id = $2
            `,
            [presetSemesterId, Number(sem.id)]
          );
        }
      }
    }

    const studyContextByCourseIdAndAdmissionId = new Map();
    for (const row of courseAdmissionRows.rows || []) {
      const admissionId = Number(row.admission_id);
      const courseId = Number(row.course_id);
      const cohortId = cohortIdByAdmissionId.get(admissionId);
      if (!cohortId) continue;
      const contextRows = await client.query(
        `
          SELECT sc.id
          FROM study_contexts sc
          JOIN study_context_course_bindings sccb ON sccb.study_context_id = sc.id
          WHERE sc.cohort_id = $1
            AND sccb.course_id = $2
          ORDER BY sc.stage_number, sc.campus_key, sc.id
        `,
        [cohortId, courseId]
      );
      if (contextRows.rows && contextRows.rows.length === 1) {
        studyContextByCourseIdAndAdmissionId.set(`${admissionId}:${courseId}`, Number(contextRows.rows[0].id));
      }
    }

    for (const user of (await client.query(
      `
        SELECT id, course_id, admission_id, study_program_id, study_track
        FROM users
        ORDER BY id
      `
    )).rows || []) {
      const userId = Number(user.id);
      const courseId = Number(user.course_id);
      const admissionId = Number(user.admission_id);
      if (!userId || !courseId || !admissionId) {
        continue;
      }
      const contextId = studyContextByCourseIdAndAdmissionId.get(`${admissionId}:${courseId}`);
      if (!contextId) {
        await enqueueModeration(client, {
          dedupeKey: buildModerationKey('user', userId, 'study-context-missing', admissionId, courseId),
          sourceKind: 'user',
          sourceId: userId,
          issueCode: 'study_context_missing',
          severity: 'high',
          title: 'User study context is missing',
          summary: `Could not resolve a unique study context for user ${userId}.`,
          payload: {
            user_id: userId,
            course_id: courseId,
            admission_id: admissionId,
            study_program_id: user.study_program_id || null,
            study_track: user.study_track || null,
          },
        });
        continue;
      }
      await client.query(
        `
          UPDATE users
          SET study_context_id = $1
          WHERE id = $2
            AND study_context_id IS NULL
        `,
        [contextId, userId]
      );
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  id: '041_academic_setup_contexts',
  up,
};
