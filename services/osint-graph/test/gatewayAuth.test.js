'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { signAssertion, createAssertionVerifier } = require('../src/auth/gatewayAssertion');

test('gateway assertions validate once and reject replay or tampering', () => {
  const now = 1_800_000_000_000;
  const fields = { actorId: 42, label: 'OSINT Operator', timestamp: Math.floor(now / 1000), nonce: '12345678-1234-1234-1234-123456789abc' };
  const secret = 'a-secure-test-secret-with-32-characters';
  const headers = {
    'x-studerria-osint-actor': String(fields.actorId), 'x-studerria-osint-label': fields.label,
    'x-studerria-osint-timestamp': String(fields.timestamp), 'x-studerria-osint-nonce': fields.nonce,
    'x-studerria-osint-signature': signAssertion(fields, secret),
  };
  const verify = createAssertionVerifier({ secret, now: () => now });
  assert.deepEqual(verify(headers), { ok: true, actor: { id: 42, label: 'OSINT Operator' } });
  assert.equal(verify(headers).reason, 'replayed_assertion');
  const tampered = { ...headers, 'x-studerria-osint-nonce': 'ffffffff-1234-1234-1234-123456789abc' };
  assert.equal(verify(tampered).reason, 'invalid_signature');
});
