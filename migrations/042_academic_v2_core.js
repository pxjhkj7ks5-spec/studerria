const DEFAULT_TRACKS = ['bachelor', 'master', 'teacher'];
const SHOULD_IMPORT_LEGACY_ACADEMIC_V2 = String(process.env.ACADEMIC_V2_IMPORT_LEGACY || '')
  .trim()
  .toLowerCase() === 'true';

const ddl = [
  `
    CREATE TABLE IF NOT EXISTS academic_v2_programs (
      id SERIAL PRIMARY KEY,
      track_key TEXT NOT NULL,
      code TEXT,
      name TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 100,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      legacy_program_id INTEGER UNIQUE REFERENCES study_programs(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(track_key, name),
      CHECK (track_key IN ('bachelor', 'master', 'teacher'))
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_cohorts (
      id SERIAL PRIMARY KEY,
      program_id INTEGER NOT NULL REFERENCES academic_v2_programs(id) ON DELETE CASCADE,
      admission_year INTEGER NOT NULL,
      label TEXT NOT NULL,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      legacy_admission_id INTEGER UNIQUE REFERENCES program_admissions(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(program_id, admission_year)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_groups (
      id SERIAL PRIMARY KEY,
      cohort_id INTEGER NOT NULL REFERENCES academic_v2_cohorts(id) ON DELETE CASCADE,
      stage_number INTEGER NOT NULL DEFAULT 1,
      campus_key TEXT NOT NULL DEFAULT 'kyiv',
      code TEXT,
      label TEXT NOT NULL,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      legacy_course_id INTEGER UNIQUE REFERENCES courses(id) ON DELETE SET NULL,
      legacy_study_context_id INTEGER UNIQUE REFERENCES study_contexts(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(cohort_id, stage_number, campus_key, label),
      CHECK (campus_key IN ('kyiv', 'munich'))
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_terms (
      id SERIAL PRIMARY KEY,
      group_id INTEGER NOT NULL REFERENCES academic_v2_groups(id) ON DELETE CASCADE,
      term_number INTEGER NOT NULL,
      title TEXT NOT NULL,
      start_date TEXT,
      weeks_count INTEGER NOT NULL DEFAULT 16,
      is_active BOOLEAN NOT NULL DEFAULT FALSE,
      is_archived BOOLEAN NOT NULL DEFAULT FALSE,
      legacy_semester_id INTEGER UNIQUE REFERENCES semesters(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(group_id, term_number)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_subject_templates (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      normalized_name TEXT NOT NULL UNIQUE,
      legacy_catalog_id INTEGER UNIQUE REFERENCES subject_catalog(id) ON DELETE SET NULL,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_group_subjects (
      id SERIAL PRIMARY KEY,
      group_id INTEGER NOT NULL REFERENCES academic_v2_groups(id) ON DELETE CASCADE,
      subject_template_id INTEGER NOT NULL REFERENCES academic_v2_subject_templates(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      group_count INTEGER NOT NULL DEFAULT 1,
      default_group INTEGER NOT NULL DEFAULT 1,
      is_visible BOOLEAN NOT NULL DEFAULT TRUE,
      is_required BOOLEAN NOT NULL DEFAULT TRUE,
      is_general BOOLEAN NOT NULL DEFAULT TRUE,
      show_in_teamwork BOOLEAN NOT NULL DEFAULT TRUE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      legacy_subject_id INTEGER UNIQUE REFERENCES subjects(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(group_id, subject_template_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_group_subject_terms (
      group_subject_id INTEGER NOT NULL REFERENCES academic_v2_group_subjects(id) ON DELETE CASCADE,
      term_id INTEGER NOT NULL REFERENCES academic_v2_terms(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(group_subject_id, term_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_teacher_assignments (
      id SERIAL PRIMARY KEY,
      group_subject_id INTEGER NOT NULL REFERENCES academic_v2_group_subjects(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      is_primary BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(group_subject_id, user_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_student_enrollments (
      id SERIAL PRIMARY KEY,
      group_id INTEGER NOT NULL REFERENCES academic_v2_groups(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      is_primary BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(group_id, user_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS academic_v2_schedule_entries (
      id SERIAL PRIMARY KEY,
      group_subject_id INTEGER NOT NULL REFERENCES academic_v2_group_subjects(id) ON DELETE CASCADE,
      term_id INTEGER NOT NULL REFERENCES academic_v2_terms(id) ON DELETE CASCADE,
      group_number INTEGER NOT NULL DEFAULT 1,
      day_of_week TEXT NOT NULL,
      class_number INTEGER NOT NULL,
      week_number INTEGER NOT NULL DEFAULT 1,
      lesson_type TEXT NOT NULL DEFAULT 'lecture',
      legacy_schedule_entry_id INTEGER UNIQUE REFERENCES schedule_entries(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(group_subject_id, term_id, group_number, day_of_week, class_number, week_number, lesson_type)
    )
  `,
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS group_id INTEGER REFERENCES academic_v2_groups(id) ON DELETE SET NULL',
  'CREATE INDEX IF NOT EXISTS academic_v2_cohorts_program_idx ON academic_v2_cohorts (program_id, admission_year DESC)',
  'CREATE INDEX IF NOT EXISTS academic_v2_groups_cohort_idx ON academic_v2_groups (cohort_id, stage_number, campus_key)',
  'CREATE INDEX IF NOT EXISTS academic_v2_terms_group_idx ON academic_v2_terms (group_id, term_number)',
  'CREATE INDEX IF NOT EXISTS academic_v2_group_subjects_group_idx ON academic_v2_group_subjects (group_id, sort_order, id)',
  'CREATE INDEX IF NOT EXISTS academic_v2_teacher_assignments_subject_idx ON academic_v2_teacher_assignments (group_subject_id, user_id)',
  'CREATE INDEX IF NOT EXISTS academic_v2_student_enrollments_group_idx ON academic_v2_student_enrollments (group_id, user_id)',
  'CREATE INDEX IF NOT EXISTS academic_v2_schedule_entries_term_idx ON academic_v2_schedule_entries (term_id, day_of_week, class_number)',
];

function cleanText(value, maxLength = 160) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, Math.max(1, Number(maxLength) || 1));
}

function normalizeTrackKey(value, fallback = 'bachelor') {
  const normalized = String(value || '').trim().toLowerCase();
  if (DEFAULT_TRACKS.includes(normalized)) {
    return normalized;
  }
  return DEFAULT_TRACKS.includes(String(fallback || '').trim().toLowerCase())
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
  const lowered = cleanText(value, 80).toLowerCase();
  if (lowered.includes('munich') || lowered.includes('mюнх')) {
    return 'munich';
  }
  return fallback === 'munich' ? 'munich' : 'kyiv';
}

function normalizeStageNumber(value, fallback = 1) {
  const normalized = Number(value || 0);
  if (Number.isInteger(normalized) && normalized > 0) {
    return normalized;
  }
  const fallbackValue = Number(fallback || 0);
  return Number.isInteger(fallbackValue) && fallbackValue > 0 ? fallbackValue : 1;
}

function extractStageNumber(courseName, fallback = 1) {
  const normalized = cleanText(courseName, 120).toLowerCase();
  if (!normalized) {
    return normalizeStageNumber(fallback, 1);
  }
  const patterns = [
    /(?:^|[\s(/,.-])(\d{1,2})\s*(?:курс|course)\b/u,
    /\b(?:курс|course)\s*(\d{1,2})\b/u,
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
  return normalizeStageNumber(fallback, 1);
}

function normalizeSubjectName(value) {
  return cleanText(value, 160).toLowerCase();
}

async function hasTable(client, tableName) {
  const row = await client.query(
    `
      SELECT 1
      FROM information_schema.tables
      WHERE table_schema = CURRENT_SCHEMA()
        AND table_name = $1
      LIMIT 1
    `,
    [tableName]
  );
  return row.rows.length > 0;
}

async function hasColumn(client, tableName, columnName) {
  const row = await client.query(
    `
      SELECT 1
      FROM information_schema.columns
      WHERE table_schema = CURRENT_SCHEMA()
        AND table_name = $1
        AND column_name = $2
      LIMIT 1
    `,
    [tableName, columnName]
  );
  return row.rows.length > 0;
}

async function ensureFallbackProgramAndCohort(client, trackKey, currentYear) {
  const normalizedTrack = normalizeTrackKey(trackKey, 'bachelor');
  const code = normalizedTrack === 'master'
    ? 'MSC-V2'
    : (normalizedTrack === 'teacher' ? 'TEACHER-V2' : 'BSC-V2');
  const name = normalizedTrack === 'master'
    ? 'Master Program'
    : (normalizedTrack === 'teacher' ? 'Teacher Track' : 'Bachelor Program');
  const sortOrder = normalizedTrack === 'master' ? 20 : (normalizedTrack === 'teacher' ? 30 : 10);
  const programRow = await client.query(
    `
      INSERT INTO academic_v2_programs
        (track_key, code, name, sort_order, is_active, created_at, updated_at)
      VALUES ($1, $2, $3, $4, TRUE, NOW(), NOW())
      ON CONFLICT (track_key, name)
      DO UPDATE SET
        code = EXCLUDED.code,
        sort_order = EXCLUDED.sort_order,
        is_active = TRUE,
        updated_at = NOW()
      RETURNING id
    `,
    [normalizedTrack, code, name, sortOrder]
  );
  const programId = Number(programRow.rows[0]?.id || 0);
  const cohortRow = await client.query(
    `
      INSERT INTO academic_v2_cohorts
        (program_id, admission_year, label, is_active, created_at, updated_at)
      VALUES ($1, $2, $3, TRUE, NOW(), NOW())
      ON CONFLICT (program_id, admission_year)
      DO UPDATE SET
        label = EXCLUDED.label,
        is_active = TRUE,
        updated_at = NOW()
      RETURNING id
    `,
    [programId, currentYear, `Imported ${currentYear}`]
  );
  return {
    programId,
    cohortId: Number(cohortRow.rows[0]?.id || 0),
  };
}

async function upsertSubjectTemplate(client, {
  name,
  normalizedName,
  legacyCatalogId = null,
}) {
  const row = await client.query(
    `
      INSERT INTO academic_v2_subject_templates
        (name, normalized_name, legacy_catalog_id, is_active, created_at, updated_at)
      VALUES ($1, $2, $3, TRUE, NOW(), NOW())
      ON CONFLICT (normalized_name)
      DO UPDATE SET
        name = EXCLUDED.name,
        legacy_catalog_id = COALESCE(academic_v2_subject_templates.legacy_catalog_id, EXCLUDED.legacy_catalog_id),
        is_active = TRUE,
        updated_at = NOW()
      RETURNING id
    `,
    [cleanText(name, 160), normalizedName, legacyCatalogId]
  );
  return Number(row.rows[0]?.id || 0);
}

async function importProgramsAndCohorts(client, currentYear) {
  const programByLegacyId = new Map();
  const cohortByLegacyAdmissionId = new Map();
  const hasLegacyPrograms = await hasTable(client, 'study_programs');
  const hasLegacyAdmissions = await hasTable(client, 'program_admissions');

  if (hasLegacyPrograms) {
    const programRows = await client.query(
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
    );
    for (const row of programRows.rows || []) {
      const inserted = await client.query(
        `
          INSERT INTO academic_v2_programs
            (track_key, code, name, sort_order, is_active, legacy_program_id, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
          ON CONFLICT (legacy_program_id)
          DO UPDATE SET
            track_key = EXCLUDED.track_key,
            code = EXCLUDED.code,
            name = EXCLUDED.name,
            sort_order = EXCLUDED.sort_order,
            is_active = EXCLUDED.is_active,
            updated_at = NOW()
          RETURNING id
        `,
        [
          normalizeTrackKey(row.track_key, 'bachelor'),
          cleanText(row.code, 40) || null,
          cleanText(row.name, 160) || `Program ${row.id}`,
          Number.isInteger(Number(row.sort_order)) ? Number(row.sort_order) : 100,
          row.is_active === true || Number(row.is_active) === 1,
          Number(row.id),
        ]
      );
      programByLegacyId.set(Number(row.id), Number(inserted.rows[0]?.id || 0));
    }
  }

  if (hasLegacyAdmissions) {
    const admissionRows = await client.query(
      `
        SELECT id, program_id, admission_year, label, is_active
        FROM program_admissions
        ORDER BY program_id, admission_year DESC, id DESC
      `
    );
    for (const row of admissionRows.rows || []) {
      const programId = programByLegacyId.get(Number(row.program_id)) || null;
      if (!programId) {
        continue;
      }
      const inserted = await client.query(
        `
          INSERT INTO academic_v2_cohorts
            (program_id, admission_year, label, is_active, legacy_admission_id, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
          ON CONFLICT (legacy_admission_id)
          DO UPDATE SET
            program_id = EXCLUDED.program_id,
            admission_year = EXCLUDED.admission_year,
            label = EXCLUDED.label,
            is_active = EXCLUDED.is_active,
            updated_at = NOW()
          RETURNING id
        `,
        [
          programId,
          Number(row.admission_year || currentYear) || currentYear,
          cleanText(row.label, 120) || `Cohort ${Number(row.admission_year || currentYear) || currentYear}`,
          row.is_active === true || Number(row.is_active) === 1,
          Number(row.id),
        ]
      );
      cohortByLegacyAdmissionId.set(Number(row.id), Number(inserted.rows[0]?.id || 0));
    }
  }

  for (const trackKey of DEFAULT_TRACKS) {
    const rows = await client.query(
      `
        SELECT c.id
        FROM academic_v2_cohorts c
        JOIN academic_v2_programs p ON p.id = c.program_id
        WHERE p.track_key = $1
        LIMIT 1
      `,
      [trackKey]
    );
    if (!rows.rows.length) {
      await ensureFallbackProgramAndCohort(client, trackKey, currentYear);
    }
  }

  const fallbackPrograms = await client.query(
    `
      SELECT c.id AS cohort_id, p.track_key
      FROM academic_v2_cohorts c
      JOIN academic_v2_programs p ON p.id = c.program_id
      ORDER BY
        CASE p.track_key
          WHEN 'bachelor' THEN 0
          WHEN 'master' THEN 1
          WHEN 'teacher' THEN 2
          ELSE 3
        END,
        c.admission_year DESC,
        c.id ASC
    `
  );
  const fallbackCohortByTrack = new Map();
  for (const row of fallbackPrograms.rows || []) {
    if (!fallbackCohortByTrack.has(row.track_key)) {
      fallbackCohortByTrack.set(row.track_key, Number(row.cohort_id));
    }
  }

  return {
    programByLegacyId,
    cohortByLegacyAdmissionId,
    fallbackCohortByTrack,
  };
}

async function importSubjectTemplates(client) {
  const templateByCatalogId = new Map();
  const templateByNormalizedName = new Map();
  const hasCatalogTable = await hasTable(client, 'subject_catalog');
  const hasSubjectsTable = await hasTable(client, 'subjects');

  if (hasCatalogTable) {
    const catalogRows = await client.query(
      `
        SELECT id, name, normalized_name
        FROM subject_catalog
        ORDER BY id
      `
    );
    for (const row of catalogRows.rows || []) {
      const normalizedName = normalizeSubjectName(row.normalized_name || row.name);
      if (!normalizedName) continue;
      const templateId = await upsertSubjectTemplate(client, {
        name: row.name,
        normalizedName,
        legacyCatalogId: Number(row.id),
      });
      templateByCatalogId.set(Number(row.id), templateId);
      templateByNormalizedName.set(normalizedName, templateId);
    }
  }

  if (hasSubjectsTable) {
    const hasCatalogId = await hasColumn(client, 'subjects', 'catalog_id');
    const subjectRows = await client.query(
      `
        SELECT id, name${hasCatalogId ? ', catalog_id' : ''}
        FROM subjects
        ORDER BY id
      `
    );
    for (const row of subjectRows.rows || []) {
      const normalizedName = normalizeSubjectName(row.name);
      if (!normalizedName) continue;
      if (hasCatalogId && Number(row.catalog_id || 0) > 0 && templateByCatalogId.has(Number(row.catalog_id))) {
        continue;
      }
      if (templateByNormalizedName.has(normalizedName)) {
        continue;
      }
      const templateId = await upsertSubjectTemplate(client, {
        name: row.name,
        normalizedName,
        legacyCatalogId: null,
      });
      templateByNormalizedName.set(normalizedName, templateId);
    }
  }

  return {
    templateByCatalogId,
    templateByNormalizedName,
  };
}

async function importGroups(client, {
  cohortByLegacyAdmissionId,
  fallbackCohortByTrack,
}) {
  const currentYear = new Date().getUTCFullYear();
  const legacyCohortById = new Map();
  if (await hasTable(client, 'cohorts')) {
    const rows = await client.query(
      `
        SELECT id, legacy_admission_id
        FROM cohorts
        ORDER BY id
      `
    );
    for (const row of rows.rows || []) {
      legacyCohortById.set(Number(row.id), Number(row.legacy_admission_id || 0) || null);
    }
  }

  const admissionIdsByCourseId = new Map();
  if (await hasTable(client, 'program_admission_courses')) {
    const rows = await client.query(
      `
        SELECT admission_id, course_id
        FROM program_admission_courses
        WHERE is_visible = TRUE
        ORDER BY admission_id ASC, course_id ASC
      `
    );
    for (const row of rows.rows || []) {
      const courseId = Number(row.course_id || 0);
      const admissionId = Number(row.admission_id || 0);
      if (!courseId || !admissionId) continue;
      if (!admissionIdsByCourseId.has(courseId)) {
        admissionIdsByCourseId.set(courseId, []);
      }
      admissionIdsByCourseId.get(courseId).push(admissionId);
    }
  }

  const courseRows = await client.query(
    `
      SELECT c.id, c.name, c.location, c.is_teacher_course,
             context.id AS legacy_study_context_id,
             context.stage_number,
             context.campus_key,
             context.cohort_id AS legacy_cohort_id
      FROM courses c
      LEFT JOIN LATERAL (
        SELECT sc.id, sc.stage_number, sc.campus_key, sc.cohort_id
        FROM study_context_course_bindings sccb
        JOIN study_contexts sc ON sc.id = sccb.study_context_id
        WHERE sccb.course_id = c.id
        ORDER BY sccb.is_primary DESC, sc.id ASC
        LIMIT 1
      ) context ON TRUE
      ORDER BY c.id
    `
  );

  const groupByLegacyCourseId = new Map();
  const groupById = new Map();

  for (const row of courseRows.rows || []) {
    const legacyCourseId = Number(row.id || 0);
    if (!legacyCourseId) continue;
    const isTeacherCourse = row.is_teacher_course === true || Number(row.is_teacher_course) === 1;
    const trackKey = isTeacherCourse ? 'teacher' : 'bachelor';
    let cohortId = null;
    const legacyCohortId = Number(row.legacy_cohort_id || 0);
    if (legacyCohortId && legacyCohortById.has(legacyCohortId)) {
      const legacyAdmissionId = legacyCohortById.get(legacyCohortId);
      cohortId = cohortByLegacyAdmissionId.get(Number(legacyAdmissionId || 0)) || null;
    }
    if (!cohortId) {
      const admissionIds = admissionIdsByCourseId.get(legacyCourseId) || [];
      if (admissionIds.length === 1) {
        cohortId = cohortByLegacyAdmissionId.get(Number(admissionIds[0] || 0)) || null;
      }
    }
    if (!cohortId) {
      cohortId = fallbackCohortByTrack.get(trackKey)
        || (await ensureFallbackProgramAndCohort(client, trackKey, currentYear)).cohortId;
    }
    const stageNumber = normalizeStageNumber(row.stage_number, extractStageNumber(row.name, 1));
    const campusKey = normalizeCampusKey(row.campus_key || row.location, 'kyiv');
    const label = cleanText(row.name, 160) || `Imported group ${legacyCourseId}`;
    const code = cleanText(`legacy-course-${legacyCourseId}`, 40);
    const inserted = await client.query(
      `
        INSERT INTO academic_v2_groups
          (cohort_id, stage_number, campus_key, code, label, is_active, legacy_course_id, legacy_study_context_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7, NOW(), NOW())
        ON CONFLICT (legacy_course_id)
        DO UPDATE SET
          cohort_id = EXCLUDED.cohort_id,
          stage_number = EXCLUDED.stage_number,
          campus_key = EXCLUDED.campus_key,
          code = EXCLUDED.code,
          label = EXCLUDED.label,
          is_active = TRUE,
          legacy_study_context_id = COALESCE(academic_v2_groups.legacy_study_context_id, EXCLUDED.legacy_study_context_id),
          updated_at = NOW()
        RETURNING *
      `,
      [
        cohortId,
        stageNumber,
        campusKey,
        code || null,
        label,
        legacyCourseId,
        Number(row.legacy_study_context_id || 0) || null,
      ]
    );
    const group = inserted.rows[0];
    const normalizedGroup = {
      id: Number(group.id || 0),
      cohort_id: Number(group.cohort_id || 0),
      stage_number: Number(group.stage_number || 0) || 1,
      campus_key: cleanText(group.campus_key, 20) || 'kyiv',
      label: cleanText(group.label, 160),
      legacy_course_id: Number(group.legacy_course_id || 0) || null,
      legacy_study_context_id: Number(group.legacy_study_context_id || 0) || null,
    };
    groupByLegacyCourseId.set(legacyCourseId, normalizedGroup);
    groupById.set(normalizedGroup.id, normalizedGroup);
  }

  return {
    groupByLegacyCourseId,
    groupById,
  };
}

async function importTerms(client, { groupByLegacyCourseId }) {
  const termByLegacySemesterId = new Map();
  const termsByGroupId = new Map();
  const semesterRows = await client.query(
    `
      SELECT id, course_id, title, start_date, weeks_count, is_active, is_archived
      FROM semesters
      ORDER BY course_id, COALESCE(NULLIF(start_date, ''), '9999-12-31') ASC, id ASC
    `
  );

  const semesterRowsByCourseId = new Map();
  for (const row of semesterRows.rows || []) {
    const courseId = Number(row.course_id || 0);
    if (!courseId || !groupByLegacyCourseId.has(courseId)) continue;
    if (!semesterRowsByCourseId.has(courseId)) {
      semesterRowsByCourseId.set(courseId, []);
    }
    semesterRowsByCourseId.get(courseId).push(row);
  }

  const today = new Date().toISOString().slice(0, 10);
  for (const [courseId, rows] of semesterRowsByCourseId.entries()) {
    const group = groupByLegacyCourseId.get(courseId);
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      const inserted = await client.query(
        `
          INSERT INTO academic_v2_terms
            (group_id, term_number, title, start_date, weeks_count, is_active, is_archived, legacy_semester_id, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
          ON CONFLICT (legacy_semester_id)
          DO UPDATE SET
            group_id = EXCLUDED.group_id,
            term_number = EXCLUDED.term_number,
            title = EXCLUDED.title,
            start_date = EXCLUDED.start_date,
            weeks_count = EXCLUDED.weeks_count,
            is_active = EXCLUDED.is_active,
            is_archived = EXCLUDED.is_archived,
            updated_at = NOW()
          RETURNING *
        `,
        [
          group.id,
          index + 1,
          cleanText(row.title, 120) || `Term ${index + 1}`,
          cleanText(row.start_date, 20) || today,
          Number(row.weeks_count || 0) > 0 ? Number(row.weeks_count) : 16,
          row.is_active === true || Number(row.is_active) === 1,
          row.is_archived === true || Number(row.is_archived) === 1,
          Number(row.id),
        ]
      );
      const term = inserted.rows[0];
      const normalizedTerm = {
        id: Number(term.id || 0),
        group_id: Number(term.group_id || 0),
        term_number: Number(term.term_number || 0) || 1,
        legacy_semester_id: Number(term.legacy_semester_id || 0) || null,
      };
      termByLegacySemesterId.set(Number(row.id), normalizedTerm);
      if (!termsByGroupId.has(normalizedTerm.group_id)) {
        termsByGroupId.set(normalizedTerm.group_id, []);
      }
      termsByGroupId.get(normalizedTerm.group_id).push(normalizedTerm);
    }
  }

  return {
    termByLegacySemesterId,
    termsByGroupId,
  };
}

async function importGroupSubjects(client, {
  groupByLegacyCourseId,
  templateByCatalogId,
  templateByNormalizedName,
  termsByGroupId,
}) {
  const hasCatalogId = await hasColumn(client, 'subjects', 'catalog_id');
  const hasIsGeneral = await hasColumn(client, 'subjects', 'is_general');
  const subjectRows = await client.query(
    `
      SELECT
        id,
        name,
        group_count,
        default_group,
        show_in_teamwork,
        visible,
        is_required,
        ${hasIsGeneral ? 'is_general' : 'TRUE AS is_general'},
        course_id,
        ${hasCatalogId ? 'catalog_id' : 'NULL AS catalog_id'}
      FROM subjects
      ORDER BY course_id, id
    `
  );

  const scheduleRows = await client.query(
    `
      SELECT subject_id, semester_id
      FROM schedule_entries
      WHERE subject_id IS NOT NULL
        AND semester_id IS NOT NULL
      ORDER BY subject_id, semester_id
    `
  );
  const legacySemesterIdsBySubjectId = new Map();
  for (const row of scheduleRows.rows || []) {
    const subjectId = Number(row.subject_id || 0);
    const semesterId = Number(row.semester_id || 0);
    if (!subjectId || !semesterId) continue;
    if (!legacySemesterIdsBySubjectId.has(subjectId)) {
      legacySemesterIdsBySubjectId.set(subjectId, new Set());
    }
    legacySemesterIdsBySubjectId.get(subjectId).add(semesterId);
  }

  const groupSubjectByLegacySubjectId = new Map();
  for (const row of subjectRows.rows || []) {
    const legacyCourseId = Number(row.course_id || 0);
    const group = groupByLegacyCourseId.get(legacyCourseId) || null;
    if (!group) continue;
    const normalizedName = normalizeSubjectName(row.name);
    if (!normalizedName) continue;
    let templateId = null;
    if (Number(row.catalog_id || 0) > 0 && templateByCatalogId.has(Number(row.catalog_id))) {
      templateId = templateByCatalogId.get(Number(row.catalog_id));
    }
    if (!templateId) {
      if (!templateByNormalizedName.has(normalizedName)) {
        const insertedTemplateId = await upsertSubjectTemplate(client, {
          name: row.name,
          normalizedName,
          legacyCatalogId: Number(row.catalog_id || 0) || null,
        });
        templateByNormalizedName.set(normalizedName, insertedTemplateId);
        if (Number(row.catalog_id || 0) > 0) {
          templateByCatalogId.set(Number(row.catalog_id), insertedTemplateId);
        }
      }
      templateId = templateByNormalizedName.get(normalizedName);
    }
    const inserted = await client.query(
      `
        INSERT INTO academic_v2_group_subjects
          (group_id, subject_template_id, title, group_count, default_group, is_visible, is_required, is_general, show_in_teamwork, sort_order, legacy_subject_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
        ON CONFLICT (legacy_subject_id)
        DO UPDATE SET
          group_id = EXCLUDED.group_id,
          subject_template_id = EXCLUDED.subject_template_id,
          title = EXCLUDED.title,
          group_count = EXCLUDED.group_count,
          default_group = EXCLUDED.default_group,
          is_visible = EXCLUDED.is_visible,
          is_required = EXCLUDED.is_required,
          is_general = EXCLUDED.is_general,
          show_in_teamwork = EXCLUDED.show_in_teamwork,
          sort_order = EXCLUDED.sort_order,
          updated_at = NOW()
        RETURNING *
      `,
      [
        group.id,
        templateId,
        cleanText(row.name, 160),
        Math.max(1, Number(row.group_count || 0) || 1),
        Math.max(1, Number(row.default_group || 0) || 1),
        row.visible !== false && Number(row.visible) !== 0,
        row.is_required !== false && Number(row.is_required) !== 0,
        row.is_general === true || Number(row.is_general) === 1,
        row.show_in_teamwork !== false && Number(row.show_in_teamwork) !== 0,
        Number(row.id || 0),
        Number(row.id),
      ]
    );
    const groupSubject = {
      id: Number(inserted.rows[0]?.id || 0),
      group_id: Number(inserted.rows[0]?.group_id || 0),
      legacy_subject_id: Number(inserted.rows[0]?.legacy_subject_id || 0) || null,
    };
    groupSubjectByLegacySubjectId.set(Number(row.id), groupSubject);

    const linkedLegacySemesterIds = Array.from(legacySemesterIdsBySubjectId.get(Number(row.id)) || []);
    const fallbackTermRows = termsByGroupId.get(group.id) || [];
    const termIds = linkedLegacySemesterIds.length
      ? linkedLegacySemesterIds
          .map((legacySemesterId) => fallbackTermRows.find((term) => Number(term.legacy_semester_id || 0) === Number(legacySemesterId || 0)))
          .filter(Boolean)
          .map((term) => Number(term.id || 0))
      : fallbackTermRows.map((term) => Number(term.id || 0));
    for (const termId of Array.from(new Set(termIds)).filter((value) => Number.isInteger(value) && value > 0)) {
      await client.query(
        `
          INSERT INTO academic_v2_group_subject_terms (group_subject_id, term_id, created_at)
          VALUES ($1, $2, NOW())
          ON CONFLICT (group_subject_id, term_id) DO NOTHING
        `,
        [groupSubject.id, termId]
      );
    }
  }

  return {
    groupSubjectByLegacySubjectId,
  };
}

async function importTeacherAssignments(client, { groupSubjectByLegacySubjectId }) {
  const hasTeacherAssignments = await hasTable(client, 'teacher_offering_assignments');
  const hasSubjectOfferings = await hasTable(client, 'subject_offerings');
  if (!hasTeacherAssignments || !hasSubjectOfferings) {
    return;
  }
  const rows = await client.query(
    `
      SELECT toa.teacher_id, so.dedupe_key
      FROM teacher_offering_assignments toa
      JOIN subject_offerings so ON so.id = toa.subject_offering_id
      ORDER BY toa.teacher_id, toa.subject_offering_id
    `
  );

  for (const row of rows.rows || []) {
    const teacherId = Number(row.teacher_id || 0);
    const match = String(row.dedupe_key || '').match(/^legacy-subject:(\d+)$/);
    if (!teacherId || !match) continue;
    const groupSubject = groupSubjectByLegacySubjectId.get(Number(match[1])) || null;
    if (!groupSubject) continue;
    await client.query(
      `
        INSERT INTO academic_v2_teacher_assignments
          (group_subject_id, user_id, is_primary, created_at, updated_at)
        VALUES ($1, $2, FALSE, NOW(), NOW())
        ON CONFLICT (group_subject_id, user_id)
        DO UPDATE SET updated_at = NOW()
      `,
      [groupSubject.id, teacherId]
    );
  }
}

async function importStudentEnrollments(client, { groupByLegacyCourseId }) {
  const rows = await client.query(
    `
      SELECT id, course_id
      FROM users
      WHERE course_id IS NOT NULL
      ORDER BY id
    `
  );
  for (const row of rows.rows || []) {
    const userId = Number(row.id || 0);
    const legacyCourseId = Number(row.course_id || 0);
    const group = groupByLegacyCourseId.get(legacyCourseId) || null;
    if (!userId || !group) continue;
    await client.query(
      `
        INSERT INTO academic_v2_student_enrollments
          (group_id, user_id, is_primary, created_at, updated_at)
        VALUES ($1, $2, TRUE, NOW(), NOW())
        ON CONFLICT (group_id, user_id)
        DO UPDATE SET
          is_primary = TRUE,
          updated_at = NOW()
      `,
      [group.id, userId]
    );
    await client.query(
      `
        UPDATE users
        SET group_id = COALESCE(group_id, $1)
        WHERE id = $2
      `,
      [group.id, userId]
    );
  }
}

async function importScheduleEntries(client, {
  groupSubjectByLegacySubjectId,
  termsByGroupId,
}) {
  const hasLessonType = await hasColumn(client, 'schedule_entries', 'lesson_type');
  const rows = await client.query(
    `
      SELECT
        id,
        subject_id,
        semester_id,
        group_number,
        day_of_week,
        class_number,
        week_number,
        ${hasLessonType ? 'lesson_type' : `'lecture' AS lesson_type`}
      FROM schedule_entries
      ORDER BY semester_id, day_of_week, class_number, id
    `
  );

  for (const row of rows.rows || []) {
    const legacySubjectId = Number(row.subject_id || 0);
    const groupSubject = groupSubjectByLegacySubjectId.get(legacySubjectId) || null;
    if (!groupSubject) continue;
    const groupTerms = termsByGroupId.get(Number(groupSubject.group_id || 0)) || [];
    if (!groupTerms.length) continue;
    let term = groupTerms.find((item) => Number(item.legacy_semester_id || 0) === Number(row.semester_id || 0)) || null;
    if (!term) {
      term = groupTerms.find((item) => Number(item.term_number || 0) === 1) || groupTerms[0] || null;
    }
    if (!term) continue;
    await client.query(
      `
        INSERT INTO academic_v2_schedule_entries
          (group_subject_id, term_id, group_number, day_of_week, class_number, week_number, lesson_type, legacy_schedule_entry_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        ON CONFLICT (legacy_schedule_entry_id)
        DO UPDATE SET
          group_subject_id = EXCLUDED.group_subject_id,
          term_id = EXCLUDED.term_id,
          group_number = EXCLUDED.group_number,
          day_of_week = EXCLUDED.day_of_week,
          class_number = EXCLUDED.class_number,
          week_number = EXCLUDED.week_number,
          lesson_type = EXCLUDED.lesson_type,
          updated_at = NOW()
      `,
      [
        groupSubject.id,
        term.id,
        Math.max(1, Number(row.group_number || 0) || 1),
        cleanText(row.day_of_week, 40) || 'Monday',
        Math.max(1, Number(row.class_number || 0) || 1),
        Math.max(1, Number(row.week_number || 0) || 1),
        cleanText(row.lesson_type, 40) || 'lecture',
        Number(row.id),
      ]
    );
  }
}

async function seedAcademicV2(client) {
  const currentYear = new Date().getUTCFullYear();
  const programState = await importProgramsAndCohorts(client, currentYear);
  const templateState = await importSubjectTemplates(client);
  const groupState = await importGroups(client, programState);
  const termState = await importTerms(client, groupState);
  const groupSubjectState = await importGroupSubjects(client, {
    ...groupState,
    ...templateState,
    ...termState,
  });
  await importTeacherAssignments(client, groupSubjectState);
  await importStudentEnrollments(client, groupState);
  await importScheduleEntries(client, {
    ...groupSubjectState,
    ...termState,
  });
}

async function up(pool) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const statement of ddl) {
      await client.query(statement);
    }
    if (SHOULD_IMPORT_LEGACY_ACADEMIC_V2) {
      await seedAcademicV2(client);
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
  id: '042_academic_v2_core',
  up,
};
