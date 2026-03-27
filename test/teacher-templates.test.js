const test = require('node:test');
const assert = require('node:assert/strict');

const {
  getTeacherRequestStatus,
  normalizeHomeworkTemplateTitleInput,
  normalizeTemplateAssetIds,
  buildAppliedHomeworkAssetIds,
  listTeacherSubjectSelections,
  normalizeTeacherSubjectSelections,
  replaceTeacherSubjectsMirror,
  upsertTeacherRequestStatus,
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

test('teacher subject selections are normalized by subject and group', () => {
  assert.deepEqual(
    normalizeTeacherSubjectSelections([
      { subject_id: '12', group_number: '2' },
      { subject_id: 12, group_number: 2 },
      { subject_id: 12, group_number: null },
      { subject_id: 'bad', group_number: 1 },
    ]),
    [
      { subject_id: 12, group_number: 2, sort_order: 0 },
      { subject_id: 12, group_number: null, sort_order: 2 },
    ]
  );
});

test('teacher subjects mirror rewrites compatibility rows from normalized selections', async () => {
  const calls = [];
  const store = {
    async run(sql, params) {
      calls.push({ sql: String(sql), params });
      return { rowCount: 1 };
    },
  };

  const count = await replaceTeacherSubjectsMirror(store, 5, [
    { subject_id: 7, group_number: 2 },
    { subject_id: 7, group_number: 2 },
    { subject_id: 8, group_number: null },
  ]);

  assert.equal(count, 2);
  assert.match(calls[0].sql, /DELETE FROM teacher_subjects/i);
  assert.equal(calls[1].params[0], 5);
  assert.equal(calls[1].params[1], 7);
  assert.equal(calls[2].params[1], 8);
});

test('teacher request status falls back from rejected to pending by default', async () => {
  const store = {
    async get() {
      return { status: 'rejected' };
    },
    async run() {
      return { rowCount: 1 };
    },
  };

  const status = await upsertTeacherRequestStatus(store, 14);
  assert.equal(status, 'pending');
});

test('teacher request status helper normalizes stored status', async () => {
  const store = {
    async get() {
      return { status: 'Approved ' };
    },
  };

  const status = await getTeacherRequestStatus(store, 9);
  assert.equal(status, 'approved');
});

test('teacher subject selections helper reads compatibility rows', async () => {
  const store = {
    async all(sql, params) {
      assert.match(String(sql), /FROM teacher_subjects/i);
      assert.deepEqual(params, [21]);
      return [{ subject_id: 5, group_number: 2 }];
    },
  };

  const rows = await listTeacherSubjectSelections(store, 21);
  assert.deepEqual(rows, [{ subject_id: 5, group_number: 2 }]);
});
