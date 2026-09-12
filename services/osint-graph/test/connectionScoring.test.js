'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { scoreConnection } = require('../src/analysis/connectionScoring');

test('connection score is transparent, capped, and carries a non-evidence disclaimer', () => {
  const result = scoreConnection({
    leftId: 'a', rightId: 'b',
    entities: [{ id: 'org', type: 'ORGANIZATION' }],
    relationships: [
      { source_entity_id: 'a', target_entity_id: 'b', relationship_type: 'FOLLOWS' },
      { source_entity_id: 'b', target_entity_id: 'a', relationship_type: 'FOLLOWS' },
      { source_entity_id: 'a', target_entity_id: 'b', relationship_type: 'MENTIONS' },
    ],
    interactions: Array.from({ length: 10 }, () => ({ source_entity_id: 'a', target_entity_id: 'b' })),
    commonNeighborIds: ['org','x','y','z','q','r'],
  });
  assert.equal(result.score, 90);
  assert.deepEqual(result.components.map((item) => item.key), ['mutual_follow','common_connections','public_interactions','co_mentions','shared_organization']);
  assert.match(result.disclaimer, /not proof/i);
});
