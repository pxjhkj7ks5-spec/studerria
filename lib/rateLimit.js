function getClientIp(req) {
  const trustedIp = typeof req.ip === 'string' ? req.ip.trim() : '';
  if (trustedIp) {
    return trustedIp;
  }
  const remoteIp = typeof req.connection?.remoteAddress === 'string'
    ? req.connection.remoteAddress.trim()
    : '';
  return remoteIp || 'unknown';
}

function normalizeRateLimitKey(rawKey) {
  const normalized = String(rawKey || '').trim() || 'default:unknown';
  const separatorIndex = normalized.indexOf(':');
  if (separatorIndex < 0) {
    return {
      namespace: 'default',
      subject: normalized.slice(0, 255) || 'unknown',
    };
  }
  const namespace = normalized.slice(0, separatorIndex).trim() || 'default';
  const subject = normalized.slice(separatorIndex + 1).trim() || 'unknown';
  return {
    namespace: namespace.slice(0, 80),
    subject: subject.slice(0, 255),
  };
}

function respondRateLimitExceeded(req, res, onLimit, resetAtMs) {
  if (Number.isFinite(resetAtMs)) {
    const retryAfterSeconds = Math.max(1, Math.ceil((resetAtMs - Date.now()) / 1000));
    res.set('Retry-After', String(retryAfterSeconds));
  }
  if (onLimit) {
    return onLimit(req, res);
  }
  if (req.accepts('json') || req.path.startsWith('/api')) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  return res.status(429).send('Too many requests');
}

function createRateLimiter(options = {}) {
  const {
    pool,
    windowMs,
    max,
    keyFn,
    onLimit,
    cleanupProbability = 0.01,
  } = options;

  return async (req, res, next) => {
    const key = keyFn ? keyFn(req) : getClientIp(req);
    const { namespace, subject } = normalizeRateLimitKey(key);

    if (!pool || typeof pool.query !== 'function') {
      console.error('Rate limiter misconfigured: pool is required');
      return next();
    }

    try {
      const result = await pool.query(
        `
          INSERT INTO rate_limit_counters
            (namespace, subject, count, reset_at, created_at, updated_at)
          VALUES
            ($1, $2, 1, NOW() + ($3::bigint * INTERVAL '1 millisecond'), NOW(), NOW())
          ON CONFLICT (namespace, subject)
          DO UPDATE SET
            count = CASE
              WHEN rate_limit_counters.reset_at <= NOW() THEN 1
              ELSE rate_limit_counters.count + 1
            END,
            reset_at = CASE
              WHEN rate_limit_counters.reset_at <= NOW()
                THEN NOW() + ($3::bigint * INTERVAL '1 millisecond')
              ELSE rate_limit_counters.reset_at
            END,
            updated_at = NOW()
          RETURNING
            count,
            (EXTRACT(EPOCH FROM reset_at) * 1000)::bigint AS reset_at_ms
        `,
        [namespace, subject, Number(windowMs || 0)]
      );

      const row = result && result.rows && result.rows[0] ? result.rows[0] : null;
      const currentCount = Number(row && row.count ? row.count : 0);
      const resetAtMs = Number(row && row.reset_at_ms ? row.reset_at_ms : 0);

      if (Math.random() < cleanupProbability) {
        pool.query('DELETE FROM rate_limit_counters WHERE reset_at <= NOW()').catch((cleanupErr) => {
          console.error('Rate limiter cleanup failed', cleanupErr);
        });
      }

      if (currentCount > max) {
        return respondRateLimitExceeded(req, res, onLimit, resetAtMs);
      }
    } catch (err) {
      console.error('Rate limiter failed open', err);
      return next();
    }

    return next();
  };
}

module.exports = {
  getClientIp,
  createRateLimiter,
};
