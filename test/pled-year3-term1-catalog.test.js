const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { listBachelorCatalogEntries } = require('../lib/bachelorCatalog');
const { alignPledYear3FirstTermCatalog } = require('../lib/academicV2');
const { indexScheduleSubjects, normalizeScheduleSubjectName, parseScheduleImportText } = require('../lib/scheduleTextImport');

const expected = new Map([
  ['Соціологія. Кількісні та якісні методи дослідження у поведінкових науках', [2, true]],
  ['Міжнародний бізнес. Міжнародні фінанси', [2, true]],
  ['Політичні системи країн ЛАКБ', [1, false]],
  ['Саморозвиток Лідера та Практики командотворення', [2, true]],
  ['Міжнародне публічне право. Міжнародне економічне право, англійською', [2, true]],
  ['Інституції ЄС і ухвалення політичних рішень', [1, false]],
  ['Іспанська мова', [2, false]],
  ['Німецька мова', [1, false]],
  ['Стратегічні комунікації і GR', [2, true]],
]);

const targetEntries = () => listBachelorCatalogEntries().filter((entry) => (
  entry.suggested_stage_number === 3 && entry.suggested_term_numbers.includes(1)
));

test('year 3 first-term catalog matches the corrected curator configuration', () => {
  const entries = targetEntries();
  assert.deepEqual(entries.map((entry) => entry.display_title).sort(), [...expected.keys()].sort());
  for (const entry of entries) {
    assert.deepEqual(
      [entry.default_group_count, entry.default_flags.is_required],
      expected.get(entry.display_title)
    );
  }
  assert.equal(entries.find((entry) => entry.source_code === 'schedule.2026.year3.spanish').default_activity_preset, 'seminar_only');
  assert.equal(entries.find((entry) => entry.source_code === 'schedule.2026.year3.german').default_activity_preset, 'seminar_only');
  for (const sourceCode of ['1.1.28.', '2.1.1.3.', '2.1.4.3.', '2.2.8.']) {
    assert.ok(!entries.some((entry) => entry.source_code === sourceCode));
  }
});

test('year 3 schedule text resolves against the corrected catalog and separates Kyiv language groups', () => {
  const scheduleText = fs.readFileSync(
    path.join(__dirname, '../docs/studerria/pled-2026-course-3-semester-1.txt'),
    'utf8'
  );
  const parsed = parseScheduleImportText(scheduleText);
  assert.equal(parsed.errors.length, 0);
  assert.equal(parsed.entries.length, 26);
  const index = indexScheduleSubjects(
    targetEntries().map((entry, indexValue) => ({ ...entry, id: indexValue + 1 })),
    ['display_title', 'template_name']
  );
  for (const row of parsed.entries) {
    assert.equal(index.get(normalizeScheduleSubjectName(row.subject)).length, 1);
  }
  const spanishRows = parsed.entries.filter((row) => row.subject === 'Іспанська мова');
  const germanRows = parsed.entries.filter((row) => row.subject === 'Німецька мова');
  assert.deepEqual(spanishRows.map((row) => row.targetGroupNumbers), [[1], [1], [2], [2]]);
  assert.deepEqual(germanRows.map((row) => row.targetGroupNumbers), [[1], [1]]);
});

test('year 3 catalog reconciliation requires a transaction', async () => {
  await assert.rejects(alignPledYear3FirstTermCatalog({}), /TRANSACTION_REQUIRED/);
});
