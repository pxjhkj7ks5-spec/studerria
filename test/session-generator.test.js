const test = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeSessionGeneratorStrategy,
  parseSessionGeneratorFlag,
  parseSessionGeneratorInt,
  buildSessionGeneratorReturnHref,
  resolveSessionGeneratorWindowDates,
  formatSessionConflictSummary,
  buildSessionConflictSlotMapV2,
} = require('../lib/sessionGenerator');

test('session generator strategy normalization falls back to exams first', () => {
  assert.equal(normalizeSessionGeneratorStrategy('balanced'), 'balanced');
  assert.equal(normalizeSessionGeneratorStrategy('credits_first'), 'credits_first');
  assert.equal(normalizeSessionGeneratorStrategy('unexpected'), 'exams_first');
});

test('session generator flag and integer parsing respect fallback and bounds', () => {
  assert.equal(parseSessionGeneratorFlag('YES', false), true);
  assert.equal(parseSessionGeneratorFlag('off', true), false);
  assert.equal(parseSessionGeneratorFlag('', true), true);

  assert.equal(parseSessionGeneratorInt('', 7, 1, 10), 7);
  assert.equal(parseSessionGeneratorInt('2.6', null, 1, 10), 3);
  assert.equal(parseSessionGeneratorInt('-5', null, 1, 10), 1);
  assert.equal(parseSessionGeneratorInt('99', null, 1, 10), 10);
});

test('session generator return href preserves normalized scope and flash payload', () => {
  const href = buildSessionGeneratorReturnHref(
    {
      location: 'MUNICH',
      course_id: '12.2',
      semester_id: '9',
      draft_id: '44',
    },
    'success',
    'published ok'
  );

  assert.equal(
    href,
    '/admin/session-generator?location=munich&course_id=12&semester_id=9&draft_id=44&success=published+ok'
  );
});

test('session generator return href preserves planner state fields for redirects', () => {
  const href = buildSessionGeneratorReturnHref(
    {
      location: 'kyiv',
      course_id: 7,
      semester_id: 3,
      draft_id: 10,
      window_mode: 'days',
      start_date: '2026-03-30',
      session_days: 12,
      max_events_per_day: 3,
      include_weekends: true,
      include_consultations: false,
      respect_study_days: true,
      strategy: 'balanced',
    },
    'ok',
    'done'
  );

  assert.equal(
    href,
    '/admin/session-generator?location=kyiv&course_id=7&semester_id=3&draft_id=10&window_mode=days&start_date=2026-03-30&session_days=12&max_events_per_day=3&strategy=balanced&include_weekends=1&include_consultations=0&respect_study_days=1&ok=done'
  );
});

test('window date resolver derives fallback week ranges and normalizes week set', () => {
  const resolved = resolveSessionGeneratorWindowDates({
    form: {
      window_mode: 'weeks',
      session_weeks_count: 2,
      session_weeks_set: '',
      include_weekends: false,
      respect_study_days: true,
    },
    semester: {
      weeks_count: 6,
      start_date: '2026-02-01',
    },
    activeStudyDayNames: ['Monday', 'Wednesday'],
    parseWeekSet: () => [],
    buildDatesFromWeekNumbers: ({ weekNumbers }) => weekNumbers.map((week) => `2026-02-0${week}`),
    buildDayBuckets: () => [],
  });

  assert.equal(resolved.window_mode, 'weeks');
  assert.deepEqual(resolved.sessionWeekNumbers, [5, 6]);
  assert.equal(resolved.sessionWeeksSet, '5,6');
  assert.deepEqual(resolved.explicitSessionDates, ['2026-02-05', '2026-02-06']);
});

test('window date resolver prefers explicit dates and supports day mode buckets', () => {
  const explicitResolved = resolveSessionGeneratorWindowDates({
    form: {
      window_mode: 'weeks',
      session_weeks_count: 3,
      include_weekends: true,
    },
    semester: {
      weeks_count: 8,
    },
    explicitDates: ['2026-04-02', '2026-04-01', '2026-04-01'],
    parseWeekSet: () => [6, 7, 8],
    buildDatesFromWeekNumbers: () => ['2026-05-01'],
    buildDayBuckets: () => [],
  });

  assert.deepEqual(explicitResolved.explicitSessionDates, ['2026-04-01', '2026-04-02']);

  const dayResolved = resolveSessionGeneratorWindowDates({
    form: {
      window_mode: 'days',
      start_date: '2026-04-10',
      session_days: 3,
      max_events_per_day: 2,
      include_weekends: false,
      respect_study_days: false,
    },
    activeStudyDayNames: ['Monday'],
    parseWeekSet: () => [],
    buildDatesFromWeekNumbers: () => [],
    buildDayBuckets: () => [
      { date: '2026-04-10' },
      { date: '2026-04-11' },
      { date: '2026-04-10' },
    ],
  });

  assert.equal(dayResolved.window_mode, 'days');
  assert.deepEqual(dayResolved.explicitSessionDates, ['2026-04-10', '2026-04-11']);
});

test('session conflict slot map aggregates draft and occupied conflicts by slot', () => {
  const slotMap = buildSessionConflictSlotMapV2({
    conflicts: [
      {
        resource_kind: 'teacher',
        teacher_name: 'Teacher One',
        type: 'draft',
        date: '2026-03-25',
        class_number: 2,
      },
      {
        resource_kind: 'room',
        room_label: 'Room 204',
        type: 'occupied',
        date: '2026-03-25',
        class_number: 2,
        details: {
          busy: {
            course_name: 'Course B',
            subject_name: 'Physics',
          },
        },
      },
      {
        resource_kind: 'teacher',
        teacher_name: 'Teacher One',
        type: 'occupied',
        date: '2026-03-25',
        class_number: 2,
        details: {
          busy: {
            course_name: 'Course B',
            subject_name: 'Physics',
          },
        },
      },
    ],
  });

  assert.deepEqual(slotMap['2026-03-25|2'], {
    date: '2026-03-25',
    class_number: 2,
    conflicts_total: 3,
    draft_conflicts: 1,
    occupied_conflicts: 2,
    reasons: [
      'Teacher One: дубль у ручному плані',
      'Room 204: зайнятий (Course B · Physics)',
      'Teacher One: зайнятий (Course B · Physics)',
    ],
    reason_text: 'Teacher One: дубль у ручному плані; Room 204: зайнятий (Course B · Physics)',
  });
});

test('session conflict summary mentions samples and unresolved rows', () => {
  const summary = formatSessionConflictSummary({
    checkedRows: 3,
    conflicts: [
      {
        resource_kind: 'teacher',
        teacher_name: 'Teacher One',
        type: 'draft',
        date: '2026-03-25',
        class_number: 2,
      },
      {
        resource_kind: 'room',
        room_label: 'Room 204',
        type: 'occupied',
        date: '2026-03-26',
        class_number: 4,
        details: {
          busy: {
            course_name: 'Course B',
            subject_name: 'Physics',
            group_number: 2,
          },
        },
      },
    ],
    unresolvedRows: [{ subject_id: 99 }],
  });

  assert.match(summary, /Teacher One/);
  assert.match(summary, /Room 204/);
  assert.match(summary, /2026-03-26/);
  assert.match(summary, /Physics/);
  assert.match(summary, /1/);
});
