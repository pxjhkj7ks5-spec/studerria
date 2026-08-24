const test = require('node:test');
const assert = require('node:assert/strict');
const { parseScheduleImportText } = require('../lib/scheduleTextImport');

test('parses the assistant-friendly Studerria schedule format', () => {
  const result = parseScheduleImportText(`
STUDERRIA_SCHEDULE_V1
# Предмет | Тип | День | Пара | Тижні | Групи
Міжнародне право | лекція | понеділок | 2 | 1-3, 5 | усі
Англійська мова\tсемінар\tвівторок\t1\t2-4\t1, 2, 3
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
  });
  assert.deepEqual(result.entries[1].targetGroupNumbers, [1, 2, 3]);
});

test('returns line-specific validation errors', () => {
  const result = parseScheduleImportText('Предмет | лекція | невідомо | 15 | x | 2');
  assert.equal(result.entries.length, 0);
  assert.ok(result.errors.length >= 4);
  assert.ok(result.errors.every((error) => error.lineNumber === 1));
});
