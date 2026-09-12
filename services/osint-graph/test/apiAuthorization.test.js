'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');
const { signAssertion } = require('../src/auth/gatewayAssertion');

const secret = 'api-authorization-test-secret-32-chars';
const config = { gatewaySecret: secret, assertionMaxAgeSeconds: 60, rateLimitPerMinute: 10, maxImportBytes: 1024 * 1024, isProduction: false, maxGraphNodes: 500, warningGraphNodes: 300, maxGraphRelationships: 2000, maxImportRecords: 5000 };
const store = { listInvestigations: async () => [], health: async () => ({ database: 'studerria_osint', user: 'studerria_osint' }) };
const app = createApp({ config, store, collectors: new Map(), executor: { enqueue() {} } });

function signedHeaders() {
  const fields = { actorId: 7, label: 'Test Operator', timestamp: Math.floor(Date.now() / 1000), nonce: `12345678-1234-1234-1234-${String(Date.now()).padStart(12, '0').slice(-12)}` };
  return {
    'x-studerria-osint-actor': String(fields.actorId), 'x-studerria-osint-label': fields.label,
    'x-studerria-osint-timestamp': String(fields.timestamp), 'x-studerria-osint-nonce': fields.nonce,
    'x-studerria-osint-signature': signAssertion(fields, secret),
  };
}

test('product API rejects requests without a valid gateway assertion', async () => {
  const result = await request(app).get('/api/osint/investigations');
  assert.equal(result.status, 403);
  assert.equal(result.body.error, 'gateway_forbidden');
});

test('product API accepts a fresh signed operator assertion', async () => {
  const result = await request(app).get('/api/osint/investigations').set(signedHeaders());
  assert.equal(result.status, 200);
  assert.deepEqual(result.body.investigations, []);
});

test('health endpoint exposes no secrets and does not require user identity', async () => {
  const result = await request(app).get('/api/osint/health');
  assert.equal(result.status, 200);
  assert.equal(result.body.database, 'studerria_osint');
  assert.equal(JSON.stringify(result.body).includes(secret), false);
});
