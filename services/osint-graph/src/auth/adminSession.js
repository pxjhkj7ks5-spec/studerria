'use strict';

const { createHmac, randomBytes, timingSafeEqual } = require('crypto');

function encode(value) {
  return Buffer.from(value).toString('base64url');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left || ''), 'utf8');
  const b = Buffer.from(String(right || ''), 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function passwordMatches(candidate, expected) {
  const left = createHmac('sha256', 'studerria-osint-password-compare').update(String(candidate || '')).digest();
  const right = createHmac('sha256', 'studerria-osint-password-compare').update(String(expected || '')).digest();
  return timingSafeEqual(left, right);
}

function createSessionToken({ username, secret, ttlSeconds, now = () => Date.now(), csrf = () => randomBytes(24).toString('base64url') }) {
  const issuedAt = Math.floor(now() / 1000);
  const payload = encode(JSON.stringify({ sub: username, actor_id: 1, iat: issuedAt, exp: issuedAt + ttlSeconds, csrf: csrf() }));
  const signature = createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function parseSessionToken(token, { secret, now = () => Date.now() }) {
  try {
    const [payload, signature, extra] = String(token || '').split('.');
    if (!payload || !signature || extra) return null;
    const expected = createHmac('sha256', secret).update(payload).digest('base64url');
    if (!safeEqual(signature, expected)) return null;
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    const nowSeconds = Math.floor(now() / 1000);
    if (claims.actor_id !== 1 || typeof claims.sub !== 'string' || !claims.sub || !Number.isInteger(claims.exp) || claims.exp <= nowSeconds || typeof claims.csrf !== 'string' || claims.csrf.length < 20) return null;
    return { id: 1, label: claims.sub, csrf: claims.csrf, expiresAt: claims.exp };
  } catch (_error) {
    return null;
  }
}

function parseCookies(header) {
  return String(header || '').split(';').reduce((cookies, pair) => {
    const separator = pair.indexOf('=');
    if (separator < 1) return cookies;
    const key = pair.slice(0, separator).trim();
    try { cookies[key] = decodeURIComponent(pair.slice(separator + 1).trim()); } catch (_error) { cookies[key] = ''; }
    return cookies;
  }, {});
}

function readSession(req, config) {
  const cookies = parseCookies(req.headers.cookie);
  return parseSessionToken(cookies[config.adminCookieName], { secret: config.sessionSecret });
}

function requireAdminSession(config) {
  return (req, res, next) => {
    const actor = readSession(req, config);
    if (!actor) return res.status(401).json({ ok: false, error: 'authentication_required' });
    req.osintActor = actor;
    return next();
  };
}

function requireCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (!safeEqual(req.headers['x-osint-csrf'], req.osintActor?.csrf)) return res.status(403).json({ ok: false, error: 'csrf_invalid' });
  return next();
}

module.exports = { createSessionToken, parseSessionToken, passwordMatches, readSession, requireAdminSession, requireCsrf };
