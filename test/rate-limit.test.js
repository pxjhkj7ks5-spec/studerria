const test = require('node:test');
const assert = require('node:assert/strict');

const { createRateLimiter, getClientIp } = require('../lib/rateLimit');

function createMockRes() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
    send(payload) {
      this.body = payload;
      return this;
    },
  };
}

test('getClientIp prefers req.ip over remote address', () => {
  assert.equal(getClientIp({
    ip: '203.0.113.9',
    connection: { remoteAddress: '127.0.0.1' },
  }), '203.0.113.9');
  assert.equal(getClientIp({
    connection: { remoteAddress: '127.0.0.1' },
  }), '127.0.0.1');
});

test('rate limiter returns JSON 429 for API-like requests after threshold', () => {
  const limiter = createRateLimiter({
    windowMs: 1_000,
    max: 2,
  });
  const req = {
    ip: '198.51.100.12',
    path: '/api/session',
    accepts: (type) => type === 'json',
  };
  const res = createMockRes();
  let nextCalls = 0;
  const next = () => {
    nextCalls += 1;
  };

  limiter(req, res, next);
  limiter(req, res, next);
  limiter(req, res, next);

  assert.equal(nextCalls, 2);
  assert.equal(res.statusCode, 429);
  assert.deepEqual(res.body, { error: 'Too many requests' });
});

test('rate limiter supports custom onLimit handlers', () => {
  const limiter = createRateLimiter({
    windowMs: 1_000,
    max: 0,
    onLimit: (_req, res) => res.status(429).send('blocked'),
  });
  const req = {
    ip: '198.51.100.13',
    path: '/login',
    accepts: () => false,
  };
  const res = createMockRes();
  let nextCalls = 0;

  limiter(req, res, () => {
    nextCalls += 1;
  });

  assert.equal(nextCalls, 0);
  assert.equal(res.statusCode, 429);
  assert.equal(res.body, 'blocked');
});
