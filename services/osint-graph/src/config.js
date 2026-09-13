'use strict';

function integerEnv(source, key, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number(source[key]);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(parsed)));
}

function loadConfig(source = process.env) {
  const isProduction = String(source.NODE_ENV || '').trim() === 'production';
  const databaseUrl = String(source.OSINT_DATABASE_URL || '').trim();
  const adminUsername = String(source.OSINT_ADMIN_USERNAME || 'osint-admin').trim();
  const adminPassword = String(source.OSINT_ADMIN_PASSWORD || '').trim();
  const sessionSecret = String(source.OSINT_SESSION_SECRET || '').trim();
  if (!databaseUrl) throw new Error('OSINT_DATABASE_URL is required');
  if (isProduction && (!adminUsername || adminPassword.length < 16 || sessionSecret.length < 32)) {
    throw new Error('OSINT standalone admin credentials are not configured safely');
  }
  return Object.freeze({
    isProduction,
    port: integerEnv(source, 'PORT', 8080, { min: 1, max: 65535 }),
    basePath: String(source.OSINT_BASE_PATH || '/osint').trim().replace(/\/$/, '') || '/osint',
    databaseUrl,
    adminUsername,
    adminPassword: adminPassword || 'local-only-osint-password',
    sessionSecret: sessionSecret || 'local-only-osint-session-secret-change-me',
    adminCookieName: String(source.OSINT_ADMIN_COOKIE_NAME || 'osint_admin').trim() || 'osint_admin',
    adminCookieSecure: isProduction ? String(source.OSINT_ADMIN_COOKIE_SECURE || 'true').trim().toLowerCase() !== 'false' : String(source.OSINT_ADMIN_COOKIE_SECURE || 'false').trim().toLowerCase() === 'true',
    adminSessionTtlSeconds: integerEnv(source, 'OSINT_ADMIN_SESSION_TTL_SECONDS', 28800, { min: 900, max: 604800 }),
    githubToken: String(source.OSINT_GITHUB_TOKEN || '').trim(),
    maxGraphNodes: integerEnv(source, 'OSINT_MAX_GRAPH_NODES', 500, { min: 20, max: 5000 }),
    warningGraphNodes: integerEnv(source, 'OSINT_GRAPH_WARNING_NODES', 300, { min: 10, max: 4000 }),
    maxGraphRelationships: integerEnv(source, 'OSINT_MAX_GRAPH_RELATIONSHIPS', 2000, { min: 20, max: 20000 }),
    maxImportBytes: integerEnv(source, 'OSINT_MAX_IMPORT_BYTES', 5 * 1024 * 1024, { min: 1024, max: 20 * 1024 * 1024 }),
    maxImportRecords: integerEnv(source, 'OSINT_MAX_IMPORT_RECORDS', 5000, { min: 20, max: 50000 }),
    collectorTimeoutMs: integerEnv(source, 'OSINT_COLLECTOR_TIMEOUT_MS', 15000, { min: 1000, max: 60000 }),
    webMaxPages: integerEnv(source, 'OSINT_WEB_MAX_PAGES', 5, { min: 1, max: 20 }),
    webMaxResponseBytes: integerEnv(source, 'OSINT_WEB_MAX_RESPONSE_BYTES', 2 * 1024 * 1024, { min: 4096, max: 10 * 1024 * 1024 }),
    retentionDays: integerEnv(source, 'OSINT_RETENTION_DAYS', 90, { min: 1, max: 3650 }),
    rateLimitPerMinute: integerEnv(source, 'OSINT_API_RATE_LIMIT_PER_MINUTE', 120, { min: 10, max: 2000 }),
    runConcurrency: integerEnv(source, 'OSINT_RUN_CONCURRENCY', 1, { min: 1, max: 3 }),
  });
}

module.exports = { loadConfig, integerEnv };
