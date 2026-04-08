const crypto = require('crypto');

const CSRF_TOKEN_LENGTH = 32;
const CSRF_HEADER = 'x-csrf-token';
const CSRF_FIELD = '_csrf';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const EXEMPT_PREFIXES = ['/_health', '/api/webhooks'];

function generateToken() {
  return crypto.randomBytes(CSRF_TOKEN_LENGTH).toString('hex');
}

function ensureSessionToken(session) {
  if (!session) return '';
  if (!session._csrfToken) {
    session._csrfToken = generateToken();
  }
  return session._csrfToken;
}

function getSubmittedToken(req) {
  if (req.body && typeof req.body[CSRF_FIELD] === 'string') {
    return req.body[CSRF_FIELD].trim();
  }
  const headerValue = req.get(CSRF_HEADER);
  if (typeof headerValue === 'string') {
    return headerValue.trim();
  }
  return '';
}

function isExempt(req) {
  for (const prefix of EXEMPT_PREFIXES) {
    if (req.path.startsWith(prefix)) return true;
  }
  return false;
}

function csrfProtection() {
  return function csrfMiddleware(req, res, next) {
    const token = ensureSessionToken(req.session);
    res.locals.csrfToken = token;

    if (SAFE_METHODS.has(req.method)) {
      return next();
    }
    if (isExempt(req)) {
      return next();
    }

    const submitted = getSubmittedToken(req);
    if (!submitted || !token) {
      const wantsJson = req.accepts('json') || req.path.startsWith('/api');
      if (wantsJson) {
        return res.status(403).json({ ok: false, error: 'csrf_token_invalid' });
      }
      return res.status(403).send('CSRF token missing or invalid');
    }

    if (submitted.length !== token.length) {
      return res.status(403).send('CSRF token missing or invalid');
    }

    const isValid = crypto.timingSafeEqual(
      Buffer.from(submitted),
      Buffer.from(token),
    );
    if (!isValid) {
      return res.status(403).send('CSRF token missing or invalid');
    }

    return next();
  };
}

module.exports = {
  csrfProtection,
  ensureSessionToken,
  generateToken,
  getSubmittedToken,
  CSRF_FIELD,
  CSRF_HEADER,
};
