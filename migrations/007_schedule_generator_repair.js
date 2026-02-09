const ddl = [
  `
    CREATE TABLE IF NOT EXISTS schedule_generator_runs (
      id SERIAL PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'draft',
      created_by_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      config TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS schedule_generator_items (
      id SERIAL PRIMARY KEY,
      run_id INTEGER NOT NULL REFERENCES schedule_generator_runs(id) ON DELETE CASCADE,
      course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE CASCADE,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      teacher_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      lesson_type TEXT NOT NULL DEFAULT 'lecture',
      group_number INTEGER,
      pairs_count INTEGER NOT NULL DEFAULT 1,
      weeks_set TEXT,
      fixed_day TEXT,
      fixed_class_number INTEGER,
      mirror_key TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS schedule_generator_teacher_limits (
      id SERIAL PRIMARY KEY,
      run_id INTEGER NOT NULL REFERENCES schedule_generator_runs(id) ON DELETE CASCADE,
      teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      allowed_weekdays TEXT,
      max_pairs_per_week INTEGER,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(run_id, teacher_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS schedule_generator_entries (
      id SERIAL PRIMARY KEY,
      run_id INTEGER NOT NULL REFERENCES schedule_generator_runs(id) ON DELETE CASCADE,
      course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
      semester_id INTEGER REFERENCES semesters(id) ON DELETE SET NULL,
      subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
      teacher_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      lesson_type TEXT,
      group_number INTEGER NOT NULL,
      day_of_week TEXT NOT NULL,
      class_number INTEGER NOT NULL,
      week_number INTEGER NOT NULL,
      is_mirror BOOLEAN NOT NULL DEFAULT FALSE,
      mirror_key TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `,
  'CREATE INDEX IF NOT EXISTS schedule_generator_entries_run_idx ON schedule_generator_entries(run_id)',
  "ALTER TABLE schedule_generator_items ADD COLUMN IF NOT EXISTS mirror_key TEXT",
  "ALTER TABLE schedule_generator_entries ADD COLUMN IF NOT EXISTS is_mirror BOOLEAN NOT NULL DEFAULT FALSE",
  "ALTER TABLE schedule_generator_entries ADD COLUMN IF NOT EXISTS mirror_key TEXT",
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '007_schedule_generator_repair',
  up,
};
