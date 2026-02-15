const ddl = [
  `
    CREATE TABLE IF NOT EXISTS access_roles (
      id SERIAL PRIMARY KEY,
      key TEXT NOT NULL UNIQUE,
      label TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      is_system BOOLEAN NOT NULL DEFAULT false,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS access_permissions (
      id SERIAL PRIMARY KEY,
      key TEXT NOT NULL UNIQUE,
      label TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'admin_section',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS access_role_permissions (
      role_id INTEGER NOT NULL REFERENCES access_roles(id) ON DELETE CASCADE,
      permission_id INTEGER NOT NULL REFERENCES access_permissions(id) ON DELETE CASCADE,
      allowed BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(role_id, permission_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS access_role_course_access (
      role_id INTEGER NOT NULL REFERENCES access_roles(id) ON DELETE CASCADE,
      course_kind TEXT NOT NULL,
      allowed BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(role_id, course_kind),
      CHECK (course_kind IN ('regular', 'teacher'))
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS user_roles (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role_id INTEGER NOT NULL REFERENCES access_roles(id) ON DELETE CASCADE,
      is_primary BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY(user_id, role_id)
    )
  `,
  'CREATE INDEX IF NOT EXISTS user_roles_user_id_idx ON user_roles(user_id)',
  'CREATE INDEX IF NOT EXISTS user_roles_role_id_idx ON user_roles(role_id)',
  'CREATE INDEX IF NOT EXISTS access_role_permissions_role_idx ON access_role_permissions(role_id)',
  'CREATE INDEX IF NOT EXISTS access_role_course_access_role_idx ON access_role_course_access(role_id)',
  'CREATE UNIQUE INDEX IF NOT EXISTS user_roles_single_primary_idx ON user_roles(user_id) WHERE is_primary = true',
];

const permissionSeed = [
  { key: 'admin-overview', label: 'Огляд' },
  { key: 'admin-settings', label: 'Налаштування' },
  { key: 'admin-schedule', label: 'Розклад' },
  { key: 'admin-import-export', label: 'Імпорт/Експорт' },
  { key: 'admin-schedule-generator', label: 'Генератор' },
  { key: 'admin-homework', label: 'Домашні' },
  { key: 'admin-users', label: 'Користувачі' },
  { key: 'admin-teachers', label: 'Заявки викладачів' },
  { key: 'admin-subjects', label: 'Предмети' },
  { key: 'admin-semesters', label: 'Семестри' },
  { key: 'admin-courses', label: 'Курси' },
  { key: 'admin-history', label: 'Історія' },
  { key: 'admin-activity', label: 'Активність' },
  { key: 'admin-teamwork', label: 'Командна робота' },
  { key: 'admin-messages', label: 'Повідомлення' },
];

const roleSeed = [
  { key: 'admin', label: 'Адмін', description: 'Повний доступ до системи', is_system: true },
  { key: 'teacher', label: 'Викладач', description: 'Доступ викладача', is_system: true },
  { key: 'deanery', label: 'Деканат', description: 'Доступ деканату', is_system: true },
  { key: 'starosta', label: 'Староста', description: 'Доступ старости', is_system: true },
  { key: 'student', label: 'Студент', description: 'Базовий доступ студента', is_system: true },
];

const rolePermissionDefaults = {
  admin: permissionSeed.map((item) => item.key),
  deanery: ['admin-schedule', 'admin-subjects', 'admin-semesters', 'admin-courses', 'admin-overview'],
  starosta: ['admin-homework', 'admin-teamwork', 'admin-messages', 'admin-overview'],
  teacher: [],
  student: [],
};

const roleCourseDefaults = {
  admin: ['regular', 'teacher'],
  teacher: ['regular', 'teacher'],
  deanery: ['regular'],
  starosta: ['regular'],
  student: ['regular'],
};

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }

  for (const permission of permissionSeed) {
    await pool.query(
      `
        INSERT INTO access_permissions (key, label, category)
        VALUES ($1, $2, 'admin_section')
        ON CONFLICT (key) DO UPDATE SET label = EXCLUDED.label
      `,
      [permission.key, permission.label]
    );
  }

  for (const role of roleSeed) {
    await pool.query(
      `
        INSERT INTO access_roles (key, label, description, is_system, is_active)
        VALUES ($1, $2, $3, $4, true)
        ON CONFLICT (key) DO UPDATE
        SET label = EXCLUDED.label,
            description = EXCLUDED.description,
            is_system = EXCLUDED.is_system,
            updated_at = NOW()
      `,
      [role.key, role.label, role.description, role.is_system]
    );
  }

  for (const [roleKey, permissionKeys] of Object.entries(rolePermissionDefaults)) {
    if (!permissionKeys.length) continue;
    await pool.query(
      `
        INSERT INTO access_role_permissions (role_id, permission_id, allowed, created_at, updated_at)
        SELECT r.id, p.id, true, NOW(), NOW()
        FROM access_roles r
        JOIN access_permissions p ON p.key = ANY($2::text[])
        WHERE r.key = $1
        ON CONFLICT (role_id, permission_id) DO NOTHING
      `,
      [roleKey, permissionKeys]
    );
  }

  for (const [roleKey, courseKinds] of Object.entries(roleCourseDefaults)) {
    if (!courseKinds.length) continue;
    await pool.query(
      `
        INSERT INTO access_role_course_access (role_id, course_kind, allowed, created_at, updated_at)
        SELECT r.id, ck.kind, true, NOW(), NOW()
        FROM access_roles r
        CROSS JOIN LATERAL (SELECT UNNEST($2::text[]) AS kind) ck
        WHERE r.key = $1
        ON CONFLICT (role_id, course_kind) DO NOTHING
      `,
      [roleKey, courseKinds]
    );
  }

  await pool.query(
    `
      WITH normalized_users AS (
        SELECT
          u.id AS user_id,
          CASE LOWER(TRIM(COALESCE(u.role, 'student')))
            WHEN 'administrator' THEN 'admin'
            WHEN 'адмін' THEN 'admin'
            WHEN 'администратор' THEN 'admin'
            WHEN 'староста' THEN 'starosta'
            WHEN 'деканат' THEN 'deanery'
            WHEN 'викладач' THEN 'teacher'
            WHEN 'студент' THEN 'student'
            ELSE LOWER(TRIM(COALESCE(u.role, 'student')))
          END AS role_key
        FROM users u
      ),
      mapped AS (
        SELECT
          nu.user_id,
          COALESCE(ar.id, fallback.id) AS role_id
        FROM normalized_users nu
        LEFT JOIN access_roles ar ON ar.key = nu.role_key
        JOIN access_roles fallback ON fallback.key = 'student'
      )
      INSERT INTO user_roles (user_id, role_id, is_primary, created_at, updated_at)
      SELECT user_id, role_id, true, NOW(), NOW()
      FROM mapped
      ON CONFLICT (user_id, role_id) DO NOTHING
    `
  );

  await pool.query(
    `
      WITH ranked AS (
        SELECT
          ur.user_id,
          ur.role_id,
          ROW_NUMBER() OVER (
            PARTITION BY ur.user_id
            ORDER BY
              CASE ar.key
                WHEN 'admin' THEN 0
                WHEN 'teacher' THEN 1
                WHEN 'deanery' THEN 2
                WHEN 'starosta' THEN 3
                WHEN 'student' THEN 4
                ELSE 5
              END,
              ur.role_id
          ) AS rn
        FROM user_roles ur
        JOIN access_roles ar ON ar.id = ur.role_id
      )
      UPDATE user_roles ur
      SET is_primary = (ranked.rn = 1),
          updated_at = NOW()
      FROM ranked
      WHERE ur.user_id = ranked.user_id
        AND ur.role_id = ranked.role_id
    `
  );

  await pool.query(
    `
      UPDATE users u
      SET role = primary_roles.key
      FROM (
        SELECT ur.user_id, ar.key
        FROM user_roles ur
        JOIN access_roles ar ON ar.id = ur.role_id
        WHERE ur.is_primary = true
      ) AS primary_roles
      WHERE u.id = primary_roles.user_id
    `
  );
}

module.exports = {
  id: '012_rbac_roles',
  up,
};
