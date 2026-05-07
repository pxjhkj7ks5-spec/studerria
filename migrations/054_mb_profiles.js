const ddl = [
  `
    CREATE TABLE IF NOT EXISTS mb_profiles (
      id BIGSERIAL PRIMARY KEY,
      key_name TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      avatar_url TEXT,
      message_for_me TEXT NOT NULL DEFAULT '',
      animation_type TEXT NOT NULL DEFAULT 'soft-glow',
      updated_by TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (key_name IN ('userA', 'userB')),
      CHECK (animation_type IN ('soft-glow', 'clouds', 'sparkles', 'tiny-faces'))
    )
  `,
  `
    INSERT INTO mb_profiles (key_name, display_name, avatar_url, message_for_me, animation_type, updated_by)
    VALUES
      ('userA', 'Person A', NULL, '', 'soft-glow', NULL),
      ('userB', 'Person B', NULL, '', 'soft-glow', NULL)
    ON CONFLICT (key_name) DO NOTHING
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '054_mb_profiles',
  up,
};
