const test = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeSessionGeneratorStrategy,
  parseSessionGeneratorFlag,
  parseSessionGeneratorInt,
  buildSessionGeneratorReturnHref,
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
