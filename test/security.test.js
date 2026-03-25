const test = require('node:test');
const assert = require('node:assert/strict');

const {
  canAccessOperationalDetails,
  isLoopbackIpAddress,
  resolveDbSslConfig,
  resolveSessionSecret,
  resolveTrustProxySetting,
} = require('../lib/security');

test('resolveTrustProxySetting respects production and explicit overrides', () => {
  assert.equal(resolveTrustProxySetting('', { isProd: true }), 1);
  assert.equal(resolveTrustProxySetting('', { isProd: false }), false);
  assert.equal(resolveTrustProxySetting('off', { isProd: true }), false);
  assert.equal(resolveTrustProxySetting('2', { isProd: false }), 2);
  assert.equal(resolveTrustProxySetting('loopback', { isProd: false }), 'loopback');
});

test('resolveDbSslConfig requires a CA when SSL is enabled', () => {
  assert.equal(resolveDbSslConfig({ enabled: false, ca: '' }), false);
  assert.throws(
    () => resolveDbSslConfig({ enabled: true, ca: '' }),
    /DB_SSL=true requires DB_SSL_CA/i
  );
  assert.deepEqual(resolveDbSslConfig({ enabled: true, ca: 'line1\\nline2' }), {
    ca: 'line1\nline2',
    rejectUnauthorized: true,
  });
});

test('resolveSessionSecret fails fast in production and allows local fallback in dev', () => {
  assert.throws(
    () => resolveSessionSecret('', { isProd: true }),
    /SESSION_SECRET must be set in production/i
  );
  assert.deepEqual(resolveSessionSecret('', { isProd: false }), {
    secret: 'dev-secret-change-me',
    usedFallback: true,
  });
  assert.deepEqual(resolveSessionSecret(' real-secret ', { isProd: true }), {
    secret: 'real-secret',
    usedFallback: false,
  });
});

test('loopback detection accepts IPv4, IPv6, and IPv4-mapped localhost', () => {
  assert.equal(isLoopbackIpAddress('127.0.0.1'), true);
  assert.equal(isLoopbackIpAddress('::1'), true);
  assert.equal(isLoopbackIpAddress('::ffff:127.0.0.1'), true);
  assert.equal(isLoopbackIpAddress('8.8.8.8'), false);
});

test('operational access allows trusted token, staff roles, and loopback fallback', () => {
  assert.equal(canAccessOperationalDetails({
    providedToken: 'abc',
    statusAccessToken: 'abc',
    clientIp: '8.8.8.8',
  }), true);
  assert.equal(canAccessOperationalDetails({
    isAdmin: true,
    clientIp: '8.8.8.8',
  }), true);
  assert.equal(canAccessOperationalDetails({
    isDeanery: true,
    clientIp: '8.8.8.8',
  }), true);
  assert.equal(canAccessOperationalDetails({
    clientIp: '::ffff:127.0.0.1',
  }), true);
  assert.equal(canAccessOperationalDetails({
    statusAccessToken: 'server-token',
    providedToken: 'wrong-token',
    clientIp: '8.8.8.8',
  }), false);
});
