'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { isPublicIp, validateUrlShape, resolvePublicAddress, SsrfError } = require('../src/security/ssrf');

test('SSRF guard rejects loopback, private, link-local and cloud metadata addresses', async () => {
  for (const address of ['127.0.0.1','10.0.0.4','172.16.1.2','192.168.1.2','169.254.169.254','::1','fd00::1','fe80::1']) assert.equal(isPublicIp(address), false, address);
  assert.throws(() => validateUrlShape('http://metadata.google.internal/computeMetadata/v1'), SsrfError);
  assert.throws(() => validateUrlShape('http://example.org:8080'), /blocked_port/);
  await assert.rejects(() => resolvePublicAddress(new URL('https://example.org'), async () => [{ address: '10.1.2.3', family: 4 }]), /private_address/);
});

test('SSRF guard allows ordinary public addresses and HTTPS URLs', async () => {
  assert.equal(isPublicIp('1.1.1.1'), true);
  assert.equal(validateUrlShape('https://example.org/path').hostname, 'example.org');
  const record = await resolvePublicAddress(new URL('https://example.org'), async () => [{ address: '93.184.216.34', family: 4 }]);
  assert.equal(record.address, '93.184.216.34');
});
