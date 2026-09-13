'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createSessionToken, parseSessionToken, passwordMatches } = require('../src/auth/adminSession');

test('standalone session is signed, expires and carries a CSRF token', () => {
  const now = 1_800_000_000_000;
  const secret = 'standalone-session-secret-with-32-characters';
  const token = createSessionToken({ username: 'operator', secret, ttlSeconds: 3600, now: () => now, csrf: () => 'csrf-token-at-least-twenty-characters' });
  assert.deepEqual(parseSessionToken(token, { secret, now: () => now }), { id: 1, label: 'operator', csrf: 'csrf-token-at-least-twenty-characters', expiresAt: 1800003600 });
  assert.equal(parseSessionToken(`${token}tampered`, { secret, now: () => now }), null);
  assert.equal(parseSessionToken(token, { secret, now: () => now + 3_600_001 }), null);
});

test('credential comparison is exact', () => {
  assert.equal(passwordMatches('correct-password', 'correct-password'), true);
  assert.equal(passwordMatches('correct-password', 'wrong-password'), false);
});
