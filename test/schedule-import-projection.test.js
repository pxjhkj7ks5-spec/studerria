const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const parser = require('../lib/scheduleTextImport');

// Exercise the actual import orchestration with persistence boundaries stubbed.
const source = fs.readFileSync(require.resolve('../lib/academicV2'), 'utf8');
const importer = source.slice(source.indexOf('async function importScheduleText('), source.indexOf('async function saveScheduleEntryRows('));

function fixture(failAt = 0, warning = {}) {
  const calls = [];
  const subject = { id: 10, group_id: 1, title: 'Test subject', group_count: 1, term_ids: [2] };
  const context = {
    ...parser,
    normalizePositiveInt: Number,
    normalizeBoolean: Boolean,
    normalizeImportedRoomLabel: (value) => value || '',
    createScheduleImportError: (message) => new Error(message),
    listTerms: async () => [{ id: 2, group_id: 1, weeks_count: 15 }],
    applyStageTemplateToGroup: async () => {},
    listGroupSubjects: async () => [subject],
    listSubjectTemplates: async () => [],
    listGroupSubjectActivities: async () => [{ id: 20, group_subject_id: 10, group_id: 1, activity_type: 'lecture', group_count: 1 }],
    ensureImportedScheduleRooms: async () => new Map(),
    saveScheduleEntryRows: async () => {
      calls.push('save');
      if (failAt && calls.length === failAt) throw new Error('write failed');
      return { rows: [{ id: calls.length }] };
    },
    runProjectionSyncSafely: async () => { calls.push('sync'); return warning; },
  };
  vm.createContext(context);
  vm.runInContext(importer, context);
  const text = 'STUDERRIA_SCHEDULE_V2\n' + [1, 2, 3].map((pair) => `Test subject | лекція | понеділок | ${pair} | 1-15 | усі`).join('\n');
  return { calls, run: () => context.importScheduleText({}, { group_id: 1, term_id: 2, text }) };
}

test('batch synchronizes once after every row is saved', async () => {
  const f = fixture();
  assert.equal((await f.run()).importedEntries, 3);
  assert.deepEqual(f.calls, ['save', 'save', 'save', 'sync']);
});
test('partial failure still synchronizes committed rows and preserves error', async () => {
  const f = fixture(2);
  await assert.rejects(f.run(), /write failed/);
  assert.deepEqual(f.calls, ['save', 'save', 'sync']);
});
test('projection warning is returned to the route', async () => {
  const f = fixture(0, { warningMessageKey: 'projectionSyncDeferred' });
  assert.equal((await f.run()).warningMessageKey, 'projectionSyncDeferred');
});
