'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadConfig } = require('../../src/config');
const { createPool, migrate } = require('../../src/db');
const { OsintStore } = require('../../src/store');
const { parseJsonDataset } = require('../../src/import/parser');

const databaseUrl = process.env.OSINT_TEST_DATABASE_URL;

test('re-import deduplicates relationships while retaining provenance', { skip: !databaseUrl }, async () => {
  const pool = createPool(loadConfig({ NODE_ENV: 'test', OSINT_DATABASE_URL: databaseUrl }));
  try {
    await migrate(pool);
    await pool.query('TRUNCATE investigations, audit_logs CASCADE');
    const store = new OsintStore(pool);
    const investigation = await store.createInvestigation({ name: 'Dedup test', actorId: 1 });
    const dataset = parseJsonDataset(Buffer.from(JSON.stringify({
      entities: [{ id: 'a', type: 'PERSON', name: 'A' }, { id: 'b', type: 'PERSON', name: 'B' }],
      relationships: [{ source: 'a', target: 'b', type: 'LINKED_TO', source_url: 'https://example.invalid/fact' }],
    })));
    await store.importDataset(investigation.id, dataset, { actorId: 1 });
    await store.importDataset(investigation.id, dataset, { actorId: 1 });
    const counts = await pool.query(`SELECT (SELECT COUNT(*) FROM relationships) AS relationships,(SELECT COUNT(*) FROM relationship_evidence) AS evidence`);
    assert.equal(Number(counts.rows[0].relationships), 1);
    assert.equal(Number(counts.rows[0].evidence), 1);
  } finally { await pool.end(); }
});
