const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { listBachelorCatalogEntries } = require('../lib/bachelorCatalog');
const { alignPledYear1FirstTermCatalog } = require('../lib/academicV2');
const { indexScheduleSubjects, normalizeScheduleSubjectName, parseScheduleImportText } = require('../lib/scheduleTextImport');

const expected = new Map([
  ['Академічна іноземна мова', 3],
  ['Прикладна математика для ухвалення рішень', 2],
  ['Вступ до політології. Загальна теорія політики', 2],
  ['Політична думка і теорія міжнародних відносин', 2],
  ['Міжнародні відносини і світова політика', 2],
  ['Українська мова за профільним спрямуванням. Академічне письмо і публічні виступи', 2],
  ['Публічна політика і публічна дипломатія', 2],
  ['Історія великих ідей', 2],
  ['Публічна історія України та українська ідентичність', 2],
]);

const targetEntries = () => listBachelorCatalogEntries().filter((entry) => (
  entry.suggested_stage_number === 1 && entry.suggested_term_numbers.includes(1)
));

test('year 1 first-term catalog matches the corrected curator configuration', () => {
  const entries = targetEntries();
  assert.deepEqual(entries.map((entry) => entry.display_title).sort(), [...expected.keys()].sort());
  for (const entry of entries) {
    assert.equal(entry.default_group_count, expected.get(entry.display_title));
    assert.equal(entry.default_flags.is_required, true);
  }
  assert.ok(!entries.some((entry) => entry.display_title === 'Основи національного спротиву'));
  assert.equal(entries.find((entry) => entry.source_code === '1.1.2.').default_activity_preset, 'seminar_only');
  assert.equal(entries.find((entry) => entry.source_code === '1.1.3.').default_activity_preset, 'lecture_practice');
});

test('year 1 schedule text contains only catalog subjects and keeps Monday English', () => {
  const scheduleText = fs.readFileSync(
    path.join(__dirname, '../docs/studerria/pled-2026-course-1-semester-1.txt'),
    'utf8'
  );
  const parsed = parseScheduleImportText(scheduleText);
  assert.equal(parsed.errors.length, 0);
  assert.equal(parsed.entries.length, 32);
  assert.ok(!parsed.entries.some((row) => row.subject === 'Основи національного спротиву'));
  assert.equal(parsed.entries.filter((row) => row.subject === 'Академічна іноземна мова').length, 6);
  const index = indexScheduleSubjects(
    targetEntries().map((entry, indexValue) => ({ ...entry, id: indexValue + 1 })),
    ['display_title', 'template_name']
  );
  for (const row of parsed.entries) {
    assert.equal(index.get(normalizeScheduleSubjectName(row.subject)).length, 1);
  }
});

test('year 1 catalog reconciliation requires a transaction', async () => {
  await assert.rejects(alignPledYear1FirstTermCatalog({}), /TRANSACTION_REQUIRED/);
});
