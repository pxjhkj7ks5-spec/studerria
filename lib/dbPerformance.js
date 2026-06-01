const DEFAULT_SLOW_QUERY_THRESHOLD_MS = 750;

function parseSlowQueryThreshold(rawValue, fallback = DEFAULT_SLOW_QUERY_THRESHOLD_MS) {
  const value = Number(rawValue);
  if (!Number.isFinite(value)) return fallback;
  if (value < 0) return 0;
  return Math.floor(value);
}

function normalizeSqlForLog(sql = '') {
  return String(sql || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 500);
}

function buildQueryLogPayload({ sql = '', params = [], durationMs = 0, error = null } = {}) {
  const safeParams = Array.isArray(params) ? params : [];
  return {
    duration_ms: Number(durationMs || 0),
    params_count: safeParams.length,
    sql: normalizeSqlForLog(sql),
    error: error && error.message ? String(error.message).slice(0, 220) : undefined,
  };
}

function maybeLogSlowQuery({ sql = '', params = [], startedAt = 0, thresholdMs = DEFAULT_SLOW_QUERY_THRESHOLD_MS, error = null } = {}) {
  const normalizedThreshold = parseSlowQueryThreshold(thresholdMs);
  if (!normalizedThreshold) return;
  const durationMs = Date.now() - Number(startedAt || Date.now());
  if (durationMs < normalizedThreshold) return;
  const payload = buildQueryLogPayload({ sql, params, durationMs, error });
  const line = JSON.stringify(payload);
  if (error) {
    console.error('DB_SLOW_QUERY_ERROR', line);
  } else {
    console.warn('DB_SLOW_QUERY', line);
  }
}

function instrumentPgPool(pool, options = {}) {
  if (!pool || typeof pool.query !== 'function' || pool.__studerriaPerformanceInstrumented) {
    return pool;
  }
  const thresholdMs = parseSlowQueryThreshold(options.thresholdMs, DEFAULT_SLOW_QUERY_THRESHOLD_MS);
  const originalQuery = pool.query.bind(pool);
  pool.query = (...args) => {
    const startedAt = Date.now();
    const sql = args[0];
    const params = Array.isArray(args[1]) ? args[1] : [];
    const lastArg = args[args.length - 1];
    if (typeof lastArg === 'function') {
      const callback = lastArg;
      const wrappedCallback = (err, result) => {
        maybeLogSlowQuery({ sql, params, startedAt, thresholdMs, error: err });
        callback(err, result);
      };
      return originalQuery(...args.slice(0, -1), wrappedCallback);
    }
    const result = originalQuery(...args);
    if (!result || typeof result.then !== 'function') {
      maybeLogSlowQuery({ sql, params, startedAt, thresholdMs });
      return result;
    }
    return result
      .then((value) => {
        maybeLogSlowQuery({ sql, params, startedAt, thresholdMs });
        return value;
      })
      .catch((err) => {
        maybeLogSlowQuery({ sql, params, startedAt, thresholdMs, error: err });
        throw err;
      });
  };
  Object.defineProperty(pool, '__studerriaPerformanceInstrumented', {
    value: true,
    enumerable: false,
  });
  return pool;
}

const MAINTENANCE_TABLES = [
  'users',
  'schedule_entries',
  'academic_v2_schedule_entries',
  'homework',
  'messages',
  'message_targets',
  'message_reads',
  'teamwork_tasks',
  'teamwork_groups',
  'teamwork_members',
  'site_visit_events',
  'activity_log',
  'history_log',
  'login_history',
];

function quoteIdentifier(identifier = '') {
  const value = String(identifier || '').trim();
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value)) {
    throw new Error(`Invalid identifier: ${identifier}`);
  }
  return `"${value.replace(/"/g, '""')}"`;
}

function buildMaintenanceStatements(tables = MAINTENANCE_TABLES, options = {}) {
  const mode = String(options.mode || 'analyze').trim().toLowerCase();
  return (tables || []).map((table) => {
    const quoted = quoteIdentifier(table);
    if (mode === 'vacuum') return `VACUUM (ANALYZE) ${quoted}`;
    return `ANALYZE ${quoted}`;
  });
}

const RETENTION_TARGETS = [
  { table: 'site_visit_events', dateColumn: 'created_at', defaultDays: 90, supportsFreeze: true },
  { table: 'activity_log', dateColumn: 'created_at', defaultDays: 180, castTimestamp: true, supportsFreeze: true },
  { table: 'history_log', dateColumn: 'created_at', defaultDays: 365, castTimestamp: true },
  { table: 'login_history', dateColumn: 'created_at', defaultDays: 180, castTimestamp: true, supportsFreeze: true },
  { table: 'security_alert_events', dateColumn: 'created_at', defaultDays: 365, supportsFreeze: true },
  { table: 'security_risk_events', dateColumn: 'created_at', defaultDays: 365, supportsFreeze: true },
  { table: 'auth_failure_events', dateColumn: 'created_at', defaultDays: 365, supportsFreeze: true },
  { table: 'user_registration_events', dateColumn: 'created_at', defaultDays: 365, supportsFreeze: true },
  { table: 'user_role_change_events', dateColumn: 'created_at', defaultDays: 365, supportsFreeze: true },
];

function buildRetentionDeleteSql(target = {}, days = target.defaultDays) {
  const table = quoteIdentifier(target.table);
  const column = quoteIdentifier(target.dateColumn || 'created_at');
  const dateExpr = target.castTimestamp ? `${column}::timestamp` : column;
  const freezeClause = target.supportsFreeze
    ? ' AND COALESCE(is_frozen, false) = false AND (hold_until IS NULL OR hold_until < NOW())'
    : '';
  return {
    table: target.table,
    days: Math.max(1, Number(days || target.defaultDays || 1) || 1),
    sql: `DELETE FROM ${table} WHERE ${dateExpr} < NOW() - ($1::int * INTERVAL '1 day')${freezeClause}`,
  };
}

module.exports = {
  DEFAULT_SLOW_QUERY_THRESHOLD_MS,
  MAINTENANCE_TABLES,
  RETENTION_TARGETS,
  buildMaintenanceStatements,
  buildQueryLogPayload,
  buildRetentionDeleteSql,
  instrumentPgPool,
  maybeLogSlowQuery,
  normalizeSqlForLog,
  parseSlowQueryThreshold,
  quoteIdentifier,
};
