const ddl = [
  `
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS semesters (
        id SERIAL PRIMARY KEY,
        course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        start_date TEXT NOT NULL,
        weeks_count INTEGER NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 0,
        is_archived INTEGER NOT NULL DEFAULT 0
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        full_name TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL,
        password_hash TEXT,
        password TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        last_login_ip TEXT,
        last_user_agent TEXT,
        last_login_at TEXT,
        schedule_group TEXT NOT NULL DEFAULT 'A',
        course_id INTEGER REFERENCES courses(id),
        language TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS subjects (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        group_count INTEGER NOT NULL DEFAULT 1,
        default_group INTEGER NOT NULL DEFAULT 1,
        show_in_teamwork INTEGER NOT NULL DEFAULT 1,
        visible INTEGER NOT NULL DEFAULT 1,
        is_required BOOLEAN NOT NULL DEFAULT true,
        course_id INTEGER REFERENCES courses(id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS user_subject_optouts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, subject_id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS course_study_days (
        id SERIAL PRIMARY KEY,
        course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
        weekday SMALLINT NOT NULL,
        is_active BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(course_id, weekday),
        CHECK (weekday BETWEEN 1 AND 7)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS course_day_subjects (
        id SERIAL PRIMARY KEY,
        course_study_day_id INTEGER NOT NULL REFERENCES course_study_days(id) ON DELETE CASCADE,
        subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
        sort_order INT DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(course_study_day_id, subject_id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS student_groups (
        id SERIAL PRIMARY KEY,
        student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
        group_number INTEGER NOT NULL,
        UNIQUE(student_id, subject_id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS schedule_entries (
        id SERIAL PRIMARY KEY,
        subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
        group_number INTEGER NOT NULL,
        day_of_week TEXT NOT NULL,
        class_number INTEGER NOT NULL,
        week_number INTEGER NOT NULL,
        course_id INTEGER REFERENCES courses(id),
        semester_id INTEGER REFERENCES semesters(id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS homework (
        id SERIAL PRIMARY KEY,
        group_name TEXT NOT NULL,
        subject TEXT NOT NULL,
        day TEXT NOT NULL,
        time TEXT NOT NULL,
        week_number INTEGER,
        class_number INTEGER,
        subject_id INTEGER,
        group_number INTEGER,
        day_of_week TEXT,
        created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        description TEXT NOT NULL,
        class_date TEXT,
        meeting_url TEXT,
        link_url TEXT,
        file_path TEXT,
        file_name TEXT,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL,
        course_id INTEGER REFERENCES courses(id),
        semester_id INTEGER REFERENCES semesters(id),
        is_custom_deadline INTEGER NOT NULL DEFAULT 0,
        custom_due_date TEXT,
        is_control INTEGER NOT NULL DEFAULT 0
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS homework_tags (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS homework_tag_map (
        homework_id INTEGER NOT NULL REFERENCES homework(id) ON DELETE CASCADE,
        tag_id INTEGER NOT NULL REFERENCES homework_tags(id) ON DELETE CASCADE,
        UNIQUE(homework_id, tag_id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS homework_reactions (
        homework_id INTEGER NOT NULL REFERENCES homework(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        emoji TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(homework_id, user_id, emoji)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS homework_completions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        homework_id INTEGER NOT NULL REFERENCES homework(id) ON DELETE CASCADE,
        done_at TEXT NOT NULL,
        UNIQUE(user_id, homework_id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS personal_reminders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        note TEXT,
        remind_date TEXT NOT NULL,
        remind_time TEXT,
        is_done INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        course_id INTEGER REFERENCES courses(id),
        semester_id INTEGER REFERENCES semesters(id)
      )
    `,
  `
      CREATE INDEX IF NOT EXISTS personal_reminders_user_date_idx
      ON personal_reminders (user_id, remind_date)
    `,
  `
      CREATE TABLE IF NOT EXISTS history_log (
        id SERIAL PRIMARY KEY,
        actor_id INTEGER,
        actor_name TEXT,
        action TEXT NOT NULL,
        details TEXT,
        created_at TEXT NOT NULL,
        course_id INTEGER REFERENCES courses(id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS activity_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        user_name TEXT,
        action_type TEXT NOT NULL,
        target_type TEXT,
        target_id INTEGER,
        details TEXT,
        created_at TEXT NOT NULL,
        course_id INTEGER REFERENCES courses(id),
        semester_id INTEGER REFERENCES semesters(id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS login_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        full_name TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        created_at TEXT NOT NULL,
        course_id INTEGER REFERENCES courses(id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS teamwork_tasks (
        id SERIAL PRIMARY KEY,
        subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        created_by INTEGER NOT NULL REFERENCES users(id),
        created_at TEXT NOT NULL,
        due_date TEXT,
        course_id INTEGER REFERENCES courses(id),
        semester_id INTEGER REFERENCES semesters(id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS teamwork_groups (
        id SERIAL PRIMARY KEY,
        task_id INTEGER NOT NULL REFERENCES teamwork_tasks(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        leader_id INTEGER NOT NULL REFERENCES users(id),
        max_members INTEGER,
        created_at TEXT NOT NULL
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS teamwork_members (
        id SERIAL PRIMARY KEY,
        task_id INTEGER NOT NULL REFERENCES teamwork_tasks(id) ON DELETE CASCADE,
        group_id INTEGER NOT NULL REFERENCES teamwork_groups(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        joined_at TEXT NOT NULL,
        UNIQUE(task_id, user_id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS teamwork_reactions (
        task_id INTEGER NOT NULL REFERENCES teamwork_tasks(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        emoji TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(task_id, user_id, emoji)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        subject_id INTEGER REFERENCES subjects(id) ON DELETE SET NULL,
        group_number INTEGER,
        target_all INTEGER NOT NULL DEFAULT 0,
        body TEXT NOT NULL,
        created_by_id INTEGER NOT NULL REFERENCES users(id),
        created_at TEXT NOT NULL,
        course_id INTEGER REFERENCES courses(id),
        semester_id INTEGER REFERENCES semesters(id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS message_reactions (
        message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        emoji TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(message_id, user_id, emoji)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS message_targets (
        id SERIAL PRIMARY KEY,
        message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS message_reads (
        id SERIAL PRIMARY KEY,
        message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        read_at TEXT NOT NULL,
        UNIQUE(message_id, user_id)
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS subgroups (
        id SERIAL PRIMARY KEY,
        homework_id INTEGER NOT NULL REFERENCES homework(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
      )
    `,
  `
      CREATE TABLE IF NOT EXISTS subgroup_members (
        id SERIAL PRIMARY KEY,
        subgroup_id INTEGER NOT NULL REFERENCES subgroups(id) ON DELETE CASCADE,
        member_username TEXT NOT NULL,
        joined_at TEXT NOT NULL,
        UNIQUE(subgroup_id, member_username)
      )
    `,
];

const alters = [
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)',
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS language TEXT',
  'ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW()',
  'ALTER TABLE semesters ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)',
  'ALTER TABLE semesters ADD COLUMN IF NOT EXISTS title TEXT',
  'ALTER TABLE semesters ADD COLUMN IF NOT EXISTS start_date TEXT',
  'ALTER TABLE semesters ADD COLUMN IF NOT EXISTS weeks_count INTEGER',
  'ALTER TABLE semesters ADD COLUMN IF NOT EXISTS is_active INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE semesters ADD COLUMN IF NOT EXISTS is_archived INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE subjects ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)',
  'ALTER TABLE subjects ADD COLUMN IF NOT EXISTS visible INTEGER NOT NULL DEFAULT 1',
  'ALTER TABLE subjects ADD COLUMN IF NOT EXISTS is_required INTEGER NOT NULL DEFAULT 1',
  'ALTER TABLE schedule_entries ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)',
  'ALTER TABLE schedule_entries ADD COLUMN IF NOT EXISTS semester_id INTEGER REFERENCES semesters(id)',
  'ALTER TABLE homework ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)',
  'ALTER TABLE homework ADD COLUMN IF NOT EXISTS semester_id INTEGER REFERENCES semesters(id)',
  'ALTER TABLE homework ADD COLUMN IF NOT EXISTS is_custom_deadline INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE homework ADD COLUMN IF NOT EXISTS custom_due_date TEXT',
  'ALTER TABLE homework ADD COLUMN IF NOT EXISTS is_control INTEGER NOT NULL DEFAULT 0',
  "ALTER TABLE homework ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'published'",
  'ALTER TABLE homework ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ',
  'ALTER TABLE homework ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ',
  'ALTER TABLE history_log ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)',
  'ALTER TABLE login_history ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)',
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)',
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS semester_id INTEGER REFERENCES semesters(id)',
  'ALTER TABLE teamwork_tasks ADD COLUMN IF NOT EXISTS due_date TEXT',
  'ALTER TABLE messages ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)',
  'ALTER TABLE messages ADD COLUMN IF NOT EXISTS semester_id INTEGER REFERENCES semesters(id)',
  "ALTER TABLE messages ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'published'",
  'ALTER TABLE messages ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ',
  'ALTER TABLE messages ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ',
  'ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS course_id INTEGER REFERENCES courses(id)',
  'ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS semester_id INTEGER REFERENCES semesters(id)',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }

  await pool.query(
    `
      INSERT INTO courses (id, name)
      VALUES (1, '1 курс'), (2, '2 курс')
      ON CONFLICT (id) DO NOTHING
    `
  );

  await pool.query(
    `
      INSERT INTO settings (key, value) VALUES
      ('session_duration_days', '14'),
      ('max_file_size_mb', '20'),
      ('allow_homework_creation', 'true'),
      ('min_team_members', '2')
      ON CONFLICT (key) DO NOTHING
    `
  );

  for (const statement of alters) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '001_init',
  up,
};
