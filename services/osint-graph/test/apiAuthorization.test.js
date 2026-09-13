'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');

const config = {
  basePath: '/osint', adminUsername: 'operator', adminPassword: 'standalone-test-password',
  sessionSecret: 'standalone-session-secret-with-32-characters', adminCookieName: 'osint_admin',
  adminCookieSecure: false, adminSessionTtlSeconds: 28800, rateLimitPerMinute: 20,
  maxImportBytes: 1024 * 1024, isProduction: false, maxGraphNodes: 500,
  warningGraphNodes: 300, maxGraphRelationships: 2000, maxImportRecords: 5000,
};
const audits = [];
const store = {
  listInvestigations: async () => [], health: async () => ({ database: 'studerria_osint', user: 'studerria_osint' }),
  audit: async (...args) => audits.push(args),
};
const app = createApp({ config, store, collectors: new Map(), executor: { enqueue() {} } });

test('direct-link service shows its own login and rejects unauthenticated API access', async () => {
  const page = await request(app).get('/osint');
  assert.equal(page.status, 200);
  assert.match(page.text, /<h1 id="loginTitle">Вхід<\/h1>/i);
  assert.doesNotMatch(page.text, /Вхід Studerria|audit logging|Explicit evidence/i);
  const result = await request(app).get('/osint/api/investigations');
  assert.equal(result.status, 401);
  assert.equal(result.body.error, 'authentication_required');
});

test('standalone credentials create an isolated secure session', async () => {
  const agent = request.agent(app);
  const crossSite = await agent.post('/osint/api/auth/login').set('origin', 'https://example.invalid').set('host', 'studerria.com').send({ username: 'operator', password: config.adminPassword });
  assert.equal(crossSite.status, 403);
  assert.equal(crossSite.body.error, 'origin_forbidden');
  const denied = await agent.post('/osint/api/auth/login').send({ username: 'operator', password: 'wrong-password' });
  assert.equal(denied.status, 401);
  const login = await agent.post('/osint/api/auth/login').send({ username: 'operator', password: config.adminPassword });
  assert.equal(login.status, 200);
  assert.match(login.headers['set-cookie'][0], /HttpOnly/);
  assert.match(login.headers['set-cookie'][0], /SameSite=Strict/);
  const session = await agent.get('/osint/api/auth/session');
  assert.equal(session.status, 200);
  assert.equal(session.body.actor.label, 'operator');
  assert.ok(session.body.csrfToken.length >= 20);
  const rejectedLogout = await agent.post('/osint/api/auth/logout').send({});
  assert.equal(rejectedLogout.status, 403);
  assert.equal(rejectedLogout.body.error, 'csrf_invalid');
  const allowed = await agent.get('/osint/api/investigations');
  assert.equal(allowed.status, 200);
  assert.deepEqual(allowed.body.investigations, []);
  const logout = await agent.post('/osint/api/auth/logout').set('x-osint-csrf', session.body.csrfToken).send({});
  assert.equal(logout.status, 200);
  assert.ok(audits.some((entry) => entry[1] === 'auth.login'));
  assert.ok(audits.some((entry) => entry[1] === 'auth.logout'));
});

test('health endpoint exposes no credentials and does not require a session', async () => {
  const result = await request(app).get('/osint/api/health');
  assert.equal(result.status, 200);
  assert.equal(result.body.database, 'studerria_osint');
  assert.equal(JSON.stringify(result.body).includes(config.adminPassword), false);
  assert.equal(JSON.stringify(result.body).includes(config.sessionSecret), false);
});
