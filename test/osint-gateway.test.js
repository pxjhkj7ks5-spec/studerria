'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createGatewayAssertion, requireOsintAccess } = require('../middleware/osintGateway');
const navMiddleware = require('../middleware/nav');

test('Studerria gateway denies authenticated users without the OSINT permission', () => {
  const req = { session: { user: { id: 1 } }, canAccessOsint: false, originalUrl: '/api/osint/investigations' };
  const res = { statusCode: 200, body: null, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
  let nextCalled = false;
  requireOsintAccess(req, res, () => { nextCalled = true; });
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.error, 'osint_permission_required');
  assert.equal(nextCalled, false);
});

test('Studerria gateway allows only a request already marked by permission middleware', () => {
  const req = { session: { user: { id: 1 } }, canAccessOsint: true, originalUrl: '/osint' };
  let nextCalled = false;
  requireOsintAccess(req, {}, () => { nextCalled = true; });
  assert.equal(nextCalled, true);
});

test('gateway assertion contains no session or credential material', () => {
  const assertion = createGatewayAssertion({ id: 8, label: 'Operator' }, 'test-secret-with-more-than-32-characters', { now: () => 123000, nonce: () => 'nonce-value-12345678' });
  assert.deepEqual(Object.keys(assertion).sort(), ['actorId','label','nonce','signature','timestamp']);
});

test('Social Graph navigation is visible only with the OSINT permission flag', () => {
  function visibleIds(canAccessOsint) {
    const req = { path: '/home', canAccessOsint, session: { role: 'student', roles: ['student'], user: { id: 1, username: 'operator' } } };
    const res = { locals: { settings: {}, t: (key) => key } };
    navMiddleware(req, res, () => {});
    return res.locals.navItems.map((item) => item.id);
  }
  assert.equal(visibleIds(false).includes('osint-social-graph'), false);
  assert.equal(visibleIds(true).includes('osint-social-graph'), true);
});
