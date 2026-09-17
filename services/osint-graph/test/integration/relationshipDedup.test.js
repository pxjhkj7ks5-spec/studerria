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
  let investigationId;
  try {
    await migrate(pool);
    const store = new OsintStore(pool);
    const investigation = await store.createInvestigation({ name: 'Dedup test', actorId: 1 });
    investigationId = investigation.id;
    const dataset = parseJsonDataset(Buffer.from(JSON.stringify({
      entities: [{ id: 'a', type: 'PERSON', name: 'A' }, { id: 'b', type: 'PERSON', name: 'B' }],
      relationships: [{ source: 'a', target: 'b', type: 'LINKED_TO', source_url: 'https://example.invalid/fact' }],
    })));
    await store.importDataset(investigation.id, dataset, { actorId: 1 });
    await store.importDataset(investigation.id, dataset, { actorId: 1 });
    const counts = await pool.query(`SELECT (SELECT COUNT(*) FROM relationships WHERE investigation_id=$1) AS relationships,(SELECT COUNT(*) FROM relationship_evidence e JOIN relationships r ON r.id=e.relationship_id WHERE r.investigation_id=$1) AS evidence`, [investigation.id]);
    assert.equal(Number(counts.rows[0].relationships), 1);
    assert.equal(Number(counts.rows[0].evidence), 1);
  } finally { if (investigationId) await pool.query('DELETE FROM investigations WHERE id=$1', [investigationId]); await pool.end(); }
});
