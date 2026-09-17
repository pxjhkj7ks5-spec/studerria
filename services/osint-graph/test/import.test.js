'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const yazl = require('yazl');
const { parseJsonDataset, parseCsvBuffer, combineDatasets } = require('../src/import/parser');
const { parseInstagramExportDocuments, parseInstagramExportZip } = require('../src/import/instagramExport');

function zipBuffer(files) {
  return new Promise((resolve, reject) => {
    const archive = new yazl.ZipFile();
    const chunks = [];
    archive.outputStream.on('data', (chunk) => chunks.push(chunk));
    archive.outputStream.on('error', reject);
    archive.outputStream.on('end', () => resolve(Buffer.concat(chunks)));
    for (const [name, value] of Object.entries(files)) archive.addBuffer(Buffer.from(value), name);
    archive.end();
  });
}

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

test('Instagram data export becomes directional follower facts with provenance', () => {
  const dataset = parseInstagramExportDocuments([
    { name: 'followers_1.json', kind: 'followers', value: [{ string_list_data: [{ value: 'alice', timestamp: 1700000000 }] }] },
    { name: 'following.json', kind: 'following', value: { relationships_following: [{ title: 'bob', string_list_data: [{ href: 'https://www.instagram.com/bob/', timestamp: 1700000100 }] }] } },
  ], { ownerUsername: '@owner' });
  assert.deepEqual(dataset.entities.map((entity) => entity.externalId).sort(), ['instagram:alice', 'instagram:bob', 'instagram:owner']);
  assert.deepEqual(dataset.relationships.map((relationship) => [relationship.source, relationship.target]), [
    ['instagram:alice', 'instagram:owner'],
    ['instagram:owner', 'instagram:bob'],
  ]);
  assert.equal(dataset.relationships[0].confidence, 1);
  assert.equal(dataset.relationships[0].metadata.direct_platform_export, true);
});

test('Instagram export ZIP is parsed in memory and ignores unrelated archive files', async () => {
  const archive = await zipBuffer({
    'connections/followers_and_following/followers_1.json': JSON.stringify([{ string_list_data: [{ value: 'alice' }] }]),
    'connections/followers_and_following/following.json': JSON.stringify({ relationships_following: [{ title: 'bob', string_list_data: [{ value: 'bob' }] }] }),
    'media/ignored.json': JSON.stringify({ private: 'not imported' }),
  });
  const dataset = await parseInstagramExportZip(archive, { ownerUsername: 'owner', maxUncompressedBytes: 4096 });
  assert.equal(dataset.entities.length, 3);
  assert.equal(dataset.relationships.length, 2);
  assert.equal(JSON.stringify(dataset).includes('not imported'), false);
});

test('Instagram export ZIP enforces decompressed size and expected files', async () => {
  const oversized = await zipBuffer({
    'connections/followers_and_following/followers_1.json': JSON.stringify([{ string_list_data: [{ value: 'alice', padding: 'x'.repeat(1024) }] }]),
  });
  await assert.rejects(() => parseInstagramExportZip(oversized, { ownerUsername: 'owner', maxUncompressedBytes: 128 }), /instagram_export_too_large/);
  const wrong = await zipBuffer({ 'profile.json': '{}' });
  await assert.rejects(() => parseInstagramExportZip(wrong, { ownerUsername: 'owner' }), /instagram_export_files_missing/);
});

test('manual imports preserve uncertainty, custom types and metadata through normalization', () => {
  const { normalizeRelationshipInput, normalizeEntityInput } = require('../src/security/validation');
  for (const status of ['FACT', 'INFERENCE', 'HYPOTHESIS']) {
    const dataset = parseJsonDataset(Buffer.from(JSON.stringify({
      entities: [{ id: 'a', type: 'CUSTOM TYPE', name: 'A', metadata: { username: 'a@example.org', url: 'https://example.org', notes: 'line one\nline two' } }, { id: 'b', type: 'DOCUMENT', name: 'B' }],
      relationships: [{ source: 'a', target: 'b', type: 'навчався разом', label: 'Навчався разом', epistemic_status: status, explanation: 'Explicit observation', source_url: 'https://example.org/source' }],
    })));
    const relation = normalizeRelationshipInput(dataset.relationships[0]);
    assert.equal(relation.status, status);
    assert.equal(relation.explanation, 'Explicit observation');
    assert.equal(relation.metadata.label, 'Навчався разом');
    const entity = normalizeEntityInput(dataset.entities[0]);
    assert.equal(entity.username, 'a@example.org');
    assert.equal(entity.profileUrl, 'https://example.org/');
    assert.equal(entity.metadata.notes, 'line one\nline two');
  }
  assert.equal(normalizeRelationshipInput({ source: 'a', target: 'b' }).status, 'HYPOTHESIS');
});
