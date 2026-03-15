const test = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeHomeworkTemplateTitleInput,
  normalizeTemplateAssetIds,
  buildAppliedHomeworkAssetIds,
} = require('../lib/teacherTemplates');

test('template title falls back to first description line', () => {
  assert.equal(
    normalizeHomeworkTemplateTitleInput('', 'First line\nSecond line', 'Math'),
    'First line'
  );
});

test('template asset ids are normalized and deduplicated', () => {
  assert.deepEqual(normalizeTemplateAssetIds(['2', '3', '2', 'bad']), [2, 3]);
});

test('homework asset application preserves template assets first and appends uploads', () => {
  assert.deepEqual(
    buildAppliedHomeworkAssetIds({ templateAssetIds: [5, 7], uploadedAssetIds: [7, 9] }),
    [5, 7, 9]
  );
});
