'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  getWeekStartUTC,
  getWeekDayForDate,
  getAcademicWeekForSemester,
  getDateForWeekDay,
  getDateForWeekIndex,
} = require('../lib/dateUtils');
const migration = require('../migrations/078_align_active_autumn_calendar_2026');

test('academic dates are anchored to Monday even when the configured start is midweek', () => {
  assert.equal(new Date(getWeekStartUTC('2026-09-01')).toISOString().slice(0, 10), '2026-08-31');
  assert.equal(getDateForWeekDay(1, 'Friday', '2026-09-01'), '2026-09-04');
  assert.equal(getDateForWeekIndex(2, 0, '2026-09-01'), '2026-09-07');
  assert.deepEqual(getWeekDayForDate('2026-09-25', '2026-09-01'), {
    weekNumber: 4,
    dayName: 'Friday',
  });
  assert.equal(
    getAcademicWeekForSemester(new Date('2026-09-25T09:00:00Z'), {
      start_date: '2026-09-01',
      weeks_count: 15,
    }),
    4
  );
});

test('calendar migration only updates stale active autumn calendars', async () => {
  const updates = [];
  const pool = {
    async query(sql, params = []) {
      if (sql.startsWith('SELECT to_regclass')) return { rows: [{ relation: params[0] }] };
      updates.push({ sql, params });
      return { rows: [] };
    },
  };

  await migration.up(pool);

  assert.equal(updates.length, 3);
  for (const update of updates) {
    assert.deepEqual(update.params, ['2026-08-31', '2026-06-01']);
    assert.match(update.sql, /start_date IS NULL OR start_date < \$2/);
  }
  assert.match(updates[0].sql, /is_active_default = TRUE/);
  assert.match(updates[1].sql, /is_active = TRUE[\s\S]*is_archived = FALSE/);
  assert.match(updates[2].sql, /is_active = 1[\s\S]*is_archived = 0/);
});
