const DEFAULT_BUCKET_LIMIT = 50000;

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length) {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.connection?.remoteAddress || 'unknown';
}

function createRateLimiter(options = {}) {
  const {
    windowMs,
    max,
    keyFn,
    onLimit,
    bucketLimit = DEFAULT_BUCKET_LIMIT,
  } = options;
  const buckets = new Map();

  return (req, res, next) => {
    const key = keyFn ? keyFn(req) : getClientIp(req);
    const now = Date.now();
    let bucket = buckets.get(key);
    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
    }
    bucket.count += 1;
    buckets.set(key, bucket);

    if (buckets.size > bucketLimit) {
      const cutoff = now - windowMs * 2;
      for (const [k, v] of buckets.entries()) {
        if (v.resetAt < cutoff) {
          buckets.delete(k);
        }
      }
    }

    if (bucket.count > max) {
      if (onLimit) {
        return onLimit(req, res);
      }
      if (req.accepts('json') || req.path.startsWith('/api')) {
        return res.status(429).json({ error: 'Too many requests' });
      }
      return res.status(429).send('Too many requests');
    }

    return next();
  };
}

module.exports = {
  getClientIp,
  createRateLimiter,
};
