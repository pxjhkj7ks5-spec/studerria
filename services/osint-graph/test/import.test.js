'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseJsonDataset, parseCsvBuffer, combineDatasets } = require('../src/import/parser');

test('JSON import normalizes entities and relationships', () => {
  const dataset = parseJsonDataset(Buffer.from(JSON.stringify({
    entities: [{ id: 'one', type: 'person', name: 'One' }, { id: 'two', type: 'organization', name: 'Two' }],
    relationships: [{ source: 'one', target: 'two', type: 'member_of', confidence: 0.8, source_url: 'https://example.invalid/evidence' }],
  })));
  assert.equal(dataset.entities[0].type, 'PERSON');
  assert.equal(dataset.relationships[0].type, 'MEMBER_OF');
});

test('separate entity and relationship CSV files combine safely', () => {
  const entities = parseCsvBuffer(Buffer.from('id,type,name,platform,username,url\na,SOCIAL_ACCOUNT,Alpha,github,alpha,https://example.invalid/a\nb,PERSON,Beta,,,\n'));
  const relationships = parseCsvBuffer(Buffer.from('source,target,type,weight,confidence,source_url\na,b,LINKED_TO,2,0.7,https://example.invalid/e\n'));
  const result = combineDatasets([entities, relationships]);
  assert.equal(result.entities.length, 2);
  assert.equal(result.relationships.length, 1);
});

test('formula-like display text is neutralized for future spreadsheet exports', () => {
  const dataset = parseCsvBuffer(Buffer.from('id,type,name\na,PERSON,=2+3\n'));
  assert.equal(dataset.entities[0].displayName.startsWith("'="), true);
});

test('invalid relationship references remain detectable by normalized external ids', () => {
  const dataset = parseJsonDataset(Buffer.from('{"entities":[{"id":"a","type":"PERSON","name":"A"}],"relationships":[{"source":"a","target":"missing","type":"OTHER"}]}'));
  assert.equal(dataset.relationships[0].target, 'missing');
});
