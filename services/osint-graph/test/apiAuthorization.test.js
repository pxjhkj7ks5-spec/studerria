'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const yazl = require('yazl');
const { createApp } = require('../src/app');

function instagramExportZip() {
  return new Promise((resolve, reject) => {
    const archive = new yazl.ZipFile();
    const chunks = [];
    archive.outputStream.on('data', (chunk) => chunks.push(chunk));
    archive.outputStream.on('error', reject);
    archive.outputStream.on('end', () => resolve(Buffer.concat(chunks)));
    archive.addBuffer(Buffer.from(JSON.stringify([{ string_list_data: [{ value: 'public.friend' }] }])), 'connections/followers_and_following/followers_1.json');
    archive.end();
  });
}

const config = {
  basePath: '/osint', adminUsername: 'operator', adminPassword: 'standalone-test-password',
  sessionSecret: 'standalone-session-secret-with-32-characters', adminCookieName: 'osint_admin',
  adminCookieSecure: false, adminSessionTtlSeconds: 28800, rateLimitPerMinute: 20,
  maxImportBytes: 1024 * 1024, isProduction: false, maxGraphNodes: 500,
  warningGraphNodes: 300, maxGraphRelationships: 2000, maxImportRecords: 5000,
  instagramMaxConnections: 200,
};
const audits = [];
const enqueued = [];
const imports = [];
const store = {
  listInvestigations: async () => [], health: async () => ({ database: 'studerria_osint', user: 'studerria_osint' }),
  audit: async (...args) => audits.push(args),
  createRun: async ({ investigationId, kind, collector, parameters, actorId }) => ({ id: 'run-1', investigation_id: investigationId, kind, collector, parameters, created_by: actorId }),
  importDataset: async (investigationId, dataset, options) => {
    imports.push({ investigationId, dataset, options });
    return { entities: dataset.entities.length, relationships: dataset.relationships.length };
  },
};
const collectors = new Map([['instagram', { describe: () => ({ name: 'instagram-public-provider', configured: true }) }]]);
const app = createApp({ config, store, collectors, executor: { enqueue: (run) => enqueued.push(run) } });

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
  collectors.set('instagram', { describe: () => ({ name: 'instagram-public-provider', configured: false }) });
  const unconfigured = await agent.post('/osint/api/investigations/case-1/collect').set('x-osint-csrf', session.body.csrfToken).send({ collector: 'instagram', username: '@public.account' });
  assert.equal(unconfigured.status, 503);
  assert.equal(unconfigured.body.error, 'instagram_provider_not_configured');
  collectors.set('instagram', { describe: () => ({ name: 'instagram-public-provider', configured: true }) });
  const collect = await agent.post('/osint/api/investigations/case-1/collect').set('x-osint-csrf', session.body.csrfToken).send({ collector: 'instagram', username: '@public.account', direction: 'both', limit: 1000 });
  assert.equal(collect.status, 202);
  assert.equal(enqueued[0].parameters.username, '@public.account');
  assert.equal(enqueued[0].parameters.direction, 'both');
  assert.equal(enqueued[0].parameters.limit, 200);
  const archive = await instagramExportZip();
  const imported = await agent.post('/osint/api/investigations/case-1/import')
    .set('x-osint-csrf', session.body.csrfToken)
    .field('instagram_username', 'owner')
    .attach('files', archive, { filename: 'instagram-export.zip', contentType: 'application/zip' });
  assert.equal(imported.status, 201);
  assert.deepEqual(imported.body.result, { entities: 2, relationships: 1 });
  assert.equal(imports[0].options.collector, 'instagram-data-export');
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
