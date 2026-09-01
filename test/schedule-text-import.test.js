const test = require('node:test');
const assert = require('node:assert/strict');
const {
  indexScheduleSubjects,
  normalizeScheduleSubjectName,
  parseScheduleImportText,
} = require('../lib/scheduleTextImport');
const { listBachelorCatalogEntries } = require('../lib/bachelorCatalog');

const historyTitle = 'Історія європейської цивілізації. Культурна спадщина Європи';
const legacyHistoryTitle = 'Історія євроропейської цивілізації. Культурна спадщина Європи';

test('parses the assistant-friendly Studerria schedule format', () => {
  const result = parseScheduleImportText(`
STUDERRIA_SCHEDULE_V2
# Предмет | Тип | День | Пара | Тижні | Групи | Аудиторія
Міжнародне право | л | понеділок | 2 | 1-3, 5 | усі | 7-306
Англійська мова\tс\tвівторок\t1\t2-4\t1, 2, 3\tонлайн
  `);

  assert.deepEqual(result.errors, []);
  assert.equal(result.entries.length, 2);
  assert.deepEqual(result.entries[0], {
    lineNumber: 4,
    subject: 'Міжнародне право',
    activityType: 'lecture',
    dayOfWeek: 'Monday',
    classNumber: 2,
    weekNumbers: [1, 2, 3, 5],
    allGroups: true,
    targetGroupNumbers: [],
    roomLabel: '7-306',
  });
  assert.deepEqual(result.entries[1].targetGroupNumbers, [1, 2, 3]);
  assert.equal(result.entries[1].roomLabel, 'онлайн');
});

test('keeps the six-column V1 format compatible', () => {
  const result = parseScheduleImportText('STUDERRIA_SCHEDULE_V1\nПредмет | лекція | понеділок | 1 | 1-2 | усі');
  assert.deepEqual(result.errors, []);
  assert.equal(result.entries[0].roomLabel, '');
});

test('returns line-specific validation errors', () => {
  const result = parseScheduleImportText('Предмет | лекція | невідомо | 15 | x | 2');
  assert.equal(result.entries.length, 0);
  assert.ok(result.errors.length >= 4);
  assert.ok(result.errors.every((error) => error.lineNumber === 1));
});

test('schedule matching accepts corrected and legacy history spellings', () => {
  assert.equal(normalizeScheduleSubjectName(historyTitle), normalizeScheduleSubjectName(legacyHistoryTitle));
  assert.equal(normalizeScheduleSubjectName(`  ${historyTitle.toUpperCase()}  `), normalizeScheduleSubjectName(historyTitle));
});

test('corrected history name resolves to the existing catalog template id', () => {
  const template = { id: 41, name: legacyHistoryTitle };
  const index = indexScheduleSubjects([template], ['name']);
  assert.deepEqual(index.get(normalizeScheduleSubjectName(historyTitle)), [template]);
});

test('both spellings resolve to one existing course subject without duplicating it', () => {
  const subject = { id: 71, title: historyTitle, template_name: legacyHistoryTitle };
  const index = indexScheduleSubjects([subject], ['title', 'template_name']);
  assert.deepEqual(index.get(normalizeScheduleSubjectName(historyTitle)), [subject]);
  assert.deepEqual(index.get(normalizeScheduleSubjectName(legacyHistoryTitle)), [subject]);
});

test('history alias preserves ambiguity between distinct subject ids', () => {
  const subjects = [
    { id: 71, title: historyTitle },
    { id: 72, title: legacyHistoryTitle },
  ];
  const index = indexScheduleSubjects(subjects, ['title', 'template_name']);
  assert.deepEqual(index.get(normalizeScheduleSubjectName(historyTitle)), subjects);
});

test('schedule aliases do not fuzzy-match unrelated or unknown subjects', () => {
  const index = indexScheduleSubjects([{ id: 41, name: legacyHistoryTitle }], ['name']);
  assert.equal(index.get(normalizeScheduleSubjectName('Історія європейської цивілізації')), undefined);
  assert.equal(index.get(normalizeScheduleSubjectName('Політична психологія та нейромаркетинг')), undefined);
  assert.equal(normalizeScheduleSubjectName('  Соціологія  '), 'соціологія');
  assert.equal(index.has(''), false);
});

test('PDF lecture and seminar rows resolve to the same legacy history subject', () => {
  const parsed = parseScheduleImportText(`STUDERRIA_SCHEDULE_V2
${historyTitle} | лекція | четвер | 5 | 1-5,8-12 | усі | 7-302
${historyTitle} | семінар | четвер | 6 | 1-15 | усі | 7-306`);
  assert.deepEqual(parsed.errors, []);
  const subject = { id: 71, title: legacyHistoryTitle, template_name: legacyHistoryTitle };
  const index = indexScheduleSubjects([subject], ['title', 'template_name']);
  for (const entry of parsed.entries) {
    assert.equal(entry.subject, historyTitle);
    assert.deepEqual(index.get(normalizeScheduleSubjectName(entry.subject)), [subject]);
  }
});

test('catalog displays corrected history spelling without changing its stored identity', () => {
  const history = listBachelorCatalogEntries().find((entry) => entry.source_code === '2.1.3.1.');
  assert.equal(history.template_name, legacyHistoryTitle);
  assert.equal(history.display_title, historyTitle);
});
