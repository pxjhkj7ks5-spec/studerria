const ddl = [
  `
    CREATE TABLE IF NOT EXISTS rooms (
      id SERIAL PRIMARY KEY,
      course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
      campus TEXT NOT NULL DEFAULT 'kyiv',
      building TEXT,
      code TEXT,
      label TEXT,
      capacity INTEGER,
      room_type TEXT NOT NULL DEFAULT 'classroom',
      notes TEXT,
      is_active BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (campus IN ('kyiv', 'munich')),
      CHECK (room_type IN ('classroom', 'lab', 'hall', 'office', 'online', 'other'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS rooms_course_active_idx
    ON rooms (course_id, is_active, building, label)
  `,
  `
    ALTER TABLE schedule_entries
    ADD COLUMN IF NOT EXISTS room_id INTEGER REFERENCES rooms(id) ON DELETE SET NULL
  `,
  `
    ALTER TABLE homework
    ADD COLUMN IF NOT EXISTS room_id INTEGER REFERENCES rooms(id) ON DELETE SET NULL
  `,
  `
    ALTER TABLE homework
    ADD COLUMN IF NOT EXISTS source_template_id INTEGER REFERENCES teacher_homework_templates(id) ON DELETE SET NULL
  `,
  `
    CREATE TABLE IF NOT EXISTS assets (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      name TEXT,
      original_name TEXT,
      file_path TEXT NOT NULL,
      mime_type TEXT,
      file_size BIGINT,
      kind TEXT NOT NULL DEFAULT 'attachment',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS assets_user_course_idx
    ON assets (user_id, course_id, created_at DESC)
  `,
  `
    CREATE TABLE IF NOT EXISTS teacher_template_asset_map (
      template_id INTEGER NOT NULL REFERENCES teacher_homework_templates(id) ON DELETE CASCADE,
      asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (template_id, asset_id)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS teacher_template_asset_map_template_idx
    ON teacher_template_asset_map (template_id, sort_order, asset_id)
  `,
  `
    CREATE TABLE IF NOT EXISTS homework_asset_map (
      homework_id INTEGER NOT NULL REFERENCES homework(id) ON DELETE CASCADE,
      asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (homework_id, asset_id)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS homework_asset_map_homework_idx
    ON homework_asset_map (homework_id, sort_order, asset_id)
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '039_rooms_and_asset_library',
  up,
};
