const ddl = [
  `
    CREATE TABLE IF NOT EXISTS support_request_messages (
      id SERIAL PRIMARY KEY,
      request_id INTEGER NOT NULL REFERENCES support_requests(id) ON DELETE CASCADE,
      author_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      author_role TEXT NOT NULL DEFAULT 'user',
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (author_role IN ('user', 'admin'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS support_request_messages_request_idx
    ON support_request_messages (request_id, created_at ASC, id ASC)
  `,
  `
    INSERT INTO support_request_messages (request_id, author_user_id, author_role, body, created_at)
    SELECT
      sr.id,
      sr.user_id,
      'user',
      sr.body,
      COALESCE(sr.created_at, NOW())
    FROM support_requests sr
    WHERE NULLIF(TRIM(COALESCE(sr.body, '')), '') IS NOT NULL
      AND NOT EXISTS (
        SELECT 1
        FROM support_request_messages srm
        WHERE srm.request_id = sr.id
          AND srm.author_role = 'user'
      )
  `,
  `
    INSERT INTO support_request_messages (request_id, author_user_id, author_role, body, created_at)
    SELECT
      sr.id,
      sr.resolved_by,
      'admin',
      sr.admin_note,
      COALESCE(sr.resolved_at, sr.updated_at, sr.created_at, NOW())
    FROM support_requests sr
    WHERE NULLIF(TRIM(COALESCE(sr.admin_note, '')), '') IS NOT NULL
      AND NOT EXISTS (
        SELECT 1
        FROM support_request_messages srm
        WHERE srm.request_id = sr.id
          AND srm.author_role = 'admin'
      )
  `,
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '037_support_request_messages',
  up,
};
