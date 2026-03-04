const TRACK_KEYS = ['bachelor', 'master', 'teacher'];

const ddl = [
  `
    CREATE TABLE IF NOT EXISTS study_programs (
      id SERIAL PRIMARY KEY,
      track_key TEXT NOT NULL,
      code TEXT,
      name TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 100,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(track_key, name),
      CHECK (track_key IN ('bachelor', 'master', 'teacher'))
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS program_admissions (
      id SERIAL PRIMARY KEY,
      program_id INTEGER NOT NULL REFERENCES study_programs(id) ON DELETE CASCADE,
      admission_year INTEGER NOT NULL,
      label TEXT,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(program_id, admission_year)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS program_admission_courses (
      admission_id INTEGER NOT NULL REFERENCES program_admissions(id) ON DELETE CASCADE,
      course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      is_visible BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(admission_id, course_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS subject_visibility_by_admission (
      admission_id INTEGER NOT NULL REFERENCES program_admissions(id) ON DELETE CASCADE,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      is_visible BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(admission_id, subject_id)
    )
  `,
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS study_track TEXT',
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS study_program_id INTEGER REFERENCES study_programs(id)',
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS admission_id INTEGER REFERENCES program_admissions(id)',
];

async function ensureDefaultPrograms(pool) {
  const existing = await pool.query('SELECT COUNT(*)::int AS count FROM study_programs');
  if (Number(existing.rows[0]?.count || 0) > 0) {
    return;
  }

  await pool.query(
    `
      INSERT INTO study_programs (track_key, code, name, sort_order, is_active, created_at, updated_at)
      VALUES
        ('bachelor', 'BSC-CORE', 'Bachelor Program', 10, true, NOW(), NOW()),
        ('master', 'MSC-CORE', 'Master Program', 20, true, NOW(), NOW()),
        ('teacher', 'TEACHER', 'Teacher Track', 30, true, NOW(), NOW())
      ON CONFLICT (track_key, name) DO NOTHING
    `
  );

  const currentYear = new Date().getUTCFullYear();
  const cohortLabel = `Cohort ${currentYear}`;
  const programs = await pool.query(
    `
      SELECT id, track_key
      FROM study_programs
      WHERE track_key = ANY($1::text[])
    `,
    [TRACK_KEYS]
  );

  for (const program of programs.rows) {
    await pool.query(
      `
        INSERT INTO program_admissions
          (program_id, admission_year, label, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, true, NOW(), NOW())
        ON CONFLICT (program_id, admission_year) DO NOTHING
      `,
      [program.id, currentYear, cohortLabel]
    );
  }
}

async function seedCourseMappings(pool) {
  const mappingCount = await pool.query('SELECT COUNT(*)::int AS count FROM program_admission_courses');
  if (Number(mappingCount.rows[0]?.count || 0) > 0) {
    return;
  }

  const admissions = await pool.query(
    `
      SELECT
        a.id AS admission_id,
        p.track_key
      FROM program_admissions a
      JOIN study_programs p ON p.id = a.program_id
      WHERE p.is_active = true
        AND a.is_active = true
    `
  );
  if (!admissions.rows.length) {
    return;
  }

  const admissionByTrack = new Map();
  admissions.rows.forEach((row) => {
    if (!admissionByTrack.has(row.track_key)) {
      admissionByTrack.set(row.track_key, row.admission_id);
    }
  });

  const courses = await pool.query('SELECT id, is_teacher_course FROM courses ORDER BY id');
  for (const course of courses.rows) {
    const isTeacher = course.is_teacher_course === true || Number(course.is_teacher_course) === 1;
    const targets = isTeacher ? ['teacher'] : ['bachelor', 'master'];
    for (const trackKey of targets) {
      const admissionId = admissionByTrack.get(trackKey);
      if (!admissionId) continue;
      await pool.query(
        `
          INSERT INTO program_admission_courses
            (admission_id, course_id, is_visible, created_at, updated_at)
          VALUES ($1, $2, true, NOW(), NOW())
          ON CONFLICT (admission_id, course_id) DO NOTHING
        `,
        [admissionId, course.id]
      );
    }
  }
}

async function backfillUsers(pool) {
  await pool.query(
    `
      UPDATE users u
      SET study_track = CASE
        WHEN c.is_teacher_course = true THEN 'teacher'
        ELSE 'bachelor'
      END
      FROM courses c
      WHERE u.course_id = c.id
        AND (u.study_track IS NULL OR TRIM(u.study_track) = '')
    `
  );

  await pool.query(
    `
      WITH default_mapping AS (
        SELECT
          pac.course_id,
          p.track_key,
          a.program_id,
          a.id AS admission_id,
          ROW_NUMBER() OVER (
            PARTITION BY pac.course_id
            ORDER BY
              CASE p.track_key
                WHEN 'bachelor' THEN 0
                WHEN 'master' THEN 1
                WHEN 'teacher' THEN 2
                ELSE 3
              END,
              a.admission_year DESC,
              a.id DESC
          ) AS rn
        FROM program_admission_courses pac
        JOIN program_admissions a ON a.id = pac.admission_id
        JOIN study_programs p ON p.id = a.program_id
        WHERE pac.is_visible = true
          AND a.is_active = true
          AND p.is_active = true
      )
      UPDATE users u
      SET
        study_program_id = COALESCE(u.study_program_id, dm.program_id),
        admission_id = COALESCE(u.admission_id, dm.admission_id),
        study_track = COALESCE(NULLIF(TRIM(u.study_track), ''), dm.track_key)
      FROM default_mapping dm
      WHERE dm.rn = 1
        AND u.course_id = dm.course_id
    `
  );
}

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
  await ensureDefaultPrograms(pool);
  await seedCourseMappings(pool);
  await backfillUsers(pool);
}

module.exports = {
  id: '032_registration_pathways',
  up,
};
