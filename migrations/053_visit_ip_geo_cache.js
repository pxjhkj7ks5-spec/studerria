const ddl = [
  `
    CREATE TABLE IF NOT EXISTS visit_ip_geo_cache (
      ip TEXT PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'error',
      latitude DOUBLE PRECISION,
      longitude DOUBLE PRECISION,
      country TEXT,
      region TEXT,
      city TEXT,
      org TEXT,
      timezone TEXT,
      source TEXT,
      last_error TEXT,
      last_resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (status IN ('ok', 'error', 'private', 'invalid'))
    )
  `,
  'CREATE INDEX IF NOT EXISTS visit_ip_geo_cache_status_idx ON visit_ip_geo_cache(status)',
  'CREATE INDEX IF NOT EXISTS visit_ip_geo_cache_resolved_idx ON visit_ip_geo_cache(last_resolved_at DESC)',
];

async function up(pool) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

module.exports = {
  id: '053_visit_ip_geo_cache',
  up,
};
