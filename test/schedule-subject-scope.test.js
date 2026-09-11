const { test } = require('node:test');
const assert = require('node:assert/strict');
const { preferScheduleSubjectScope } = require('../lib/scheduleTextImport');
test('same-name subjects prefer the selected semester and visible record', () => {
  const rows = [{ id: 1, term_ids: [3], is_visible: true }, { id: 2, term_ids: [2], is_visible: false }, { id: 3, term_ids: [2], is_visible: true }];
  assert.deepEqual(preferScheduleSubjectScope(rows, 2), [rows[2]]);
});
test('two active same-term subjects remain ambiguous, never choose arbitrarily', () => {
  const rows = [{ id: 1, term_ids: [2], is_visible: true }, { id: 2, term_ids: [2], is_visible: true }];
  assert.deepEqual(preferScheduleSubjectScope(rows, 2), rows);
});
