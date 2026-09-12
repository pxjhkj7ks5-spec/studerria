'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { loadConfig } = require('../src/config');

test('OSINT config requires its own connection string and ignores Studerria DB credentials', () => {
  assert.throws(() => loadConfig({ NODE_ENV: 'test', DB_HOST: 'main-db', DB_NAME: 'student_portal' }), /OSINT_DATABASE_URL/);
  const config = loadConfig({ NODE_ENV: 'test', OSINT_DATABASE_URL: 'postgres://osint@osint-db/studerria_osint', DB_NAME: 'student_portal' });
  assert.equal(config.databaseUrl.includes('studerria_osint'), true);
  assert.equal(Object.hasOwn(config, 'DB_NAME'), false);
});

test('Compose keeps OSINT database private and passes no main DB credential variables to the sidecar', () => {
  const compose = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'docker', 'local', 'docker-compose.osint.yml'), 'utf8');
  const serviceBlock = compose.slice(compose.indexOf('  osint-graph:'), compose.indexOf('\n  app:', compose.indexOf('  osint-graph:')));
  assert.match(compose, /osint-db:/);
  assert.match(compose, /osint_private:\n\s+internal: true/);
  assert.match(serviceBlock, /OSINT_DATABASE_URL:/);
  assert.doesNotMatch(serviceBlock, /\n\s+DB_(HOST|USER|PASS|NAME):/);
  assert.doesNotMatch(serviceBlock, /ports:/);
});
