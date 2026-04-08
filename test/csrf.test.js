const test = require('node:test');
const assert = require('node:assert/strict');

const {
  csrfProtection,
  generateToken,
  ensureSessionToken,
  CSRF_FIELD,
  CSRF_HEADER,
} = require('../lib/csrf');

function mockReq(overrides = {}) {
  return {
    method: 'GET',
    path: '/',
    body: {},
    session: {},
    get: (header) => (overrides.headers || {})[header.toLowerCase()] || '',
    accepts: () => false,
    ...overrides,
  };
}

function mockRes() {
  const res = {
    locals: {},
    statusCode: 200,
    _body: null,
    status(code) { res.statusCode = code; return res; },
    send(body) { res._body = body; return res; },
    json(body) { res._body = body; return res; },
  };
  return res;
}

test('generateToken produces 64-char hex string', () => {
  const token = generateToken();
  assert.equal(token.length, 64);
  assert.match(token, /^[0-9a-f]{64}$/);
});

test('ensureSessionToken creates and persists token in session', () => {
  const session = {};
  const token1 = ensureSessionToken(session);
  assert.equal(token1.length, 64);
  const token2 = ensureSessionToken(session);
  assert.equal(token1, token2);
});

test('ensureSessionToken returns empty string for null session', () => {
  assert.equal(ensureSessionToken(null), '');
});

test('CSRF middleware allows safe methods without token', (_, done) => {
  const middleware = csrfProtection();
  const req = mockReq({ method: 'GET', session: {} });
  const res = mockRes();
  middleware(req, res, () => {
    assert.ok(res.locals.csrfToken);
    done();
  });
});

test('CSRF middleware rejects POST without token', () => {
  const middleware = csrfProtection();
  const session = {};
  ensureSessionToken(session);
  const req = mockReq({ method: 'POST', session, body: {} });
  const res = mockRes();
  let nextCalled = false;
  middleware(req, res, () => { nextCalled = true; });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test('CSRF middleware accepts POST with valid body token', (_, done) => {
  const middleware = csrfProtection();
  const session = {};
  const token = ensureSessionToken(session);
  const req = mockReq({ method: 'POST', session, body: { [CSRF_FIELD]: token } });
  const res = mockRes();
  middleware(req, res, () => {
    assert.equal(res.statusCode, 200);
    done();
  });
});

test('CSRF middleware accepts POST with valid header token', (_, done) => {
  const middleware = csrfProtection();
  const session = {};
  const token = ensureSessionToken(session);
  const req = mockReq({
    method: 'POST',
    session,
    body: {},
    headers: { [CSRF_HEADER]: token },
  });
  const res = mockRes();
  middleware(req, res, () => {
    assert.equal(res.statusCode, 200);
    done();
  });
});

test('CSRF middleware rejects POST with wrong token', () => {
  const middleware = csrfProtection();
  const session = {};
  ensureSessionToken(session);
  const req = mockReq({
    method: 'POST',
    session,
    body: { [CSRF_FIELD]: 'a'.repeat(64) },
  });
  const res = mockRes();
  let nextCalled = false;
  middleware(req, res, () => { nextCalled = true; });
  assert.equal(nextCalled, false);
  assert.equal(res.statusCode, 403);
});

test('CSRF middleware exempts health endpoint', (_, done) => {
  const middleware = csrfProtection();
  const req = mockReq({ method: 'POST', path: '/_health', session: {} });
  const res = mockRes();
  middleware(req, res, () => {
    done();
  });
});

test('CSRF middleware returns JSON error for API requests', () => {
  const middleware = csrfProtection();
  const session = {};
  ensureSessionToken(session);
  const req = mockReq({
    method: 'POST',
    path: '/api/something',
    session,
    body: {},
    accepts: (type) => type === 'json',
  });
  const res = mockRes();
  middleware(req, res, () => {});
  assert.equal(res.statusCode, 403);
  assert.deepEqual(res._body, { ok: false, error: 'csrf_token_invalid' });
});
