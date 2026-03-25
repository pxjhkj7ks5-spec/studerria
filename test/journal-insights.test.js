const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildRatingSnapshotPayload,
  formatRatingSnapshotCard,
  buildAttendanceHealthSummary,
  describeRatingPublishTarget,
  findRelevantRatingSnapshot,
} = require('../lib/journalInsights');

test('rating snapshot payload formats leaderboard and message body', () => {
  const payload = buildRatingSnapshotPayload({
    context: {
      scopeLabel: 'Group 1',
      scopeType: 'group',
      periodLabel: 'Semester',
      courseId: 1,
      subjectId: 3,
      groupNumber: 1,
      targetKind: 'subject',
    },
    ratingRows: [
      { student_id: 1, full_name: 'Alice', final_score: 96.4, subjects_count: 2 },
      { student_id: 2, full_name: 'Bob', final_score: 90.1, subjects_count: 1 },
    ],
    topN: 2,
    publishedAtIso: '2026-03-15T10:00:00Z',
  });
  assert.equal(payload.snapshot.top_n, 2);
  assert.match(payload.messageBody, /Group 1/);
  assert.equal(payload.snapshot.ranking_json[0].rank, 1);
});

test('rating snapshot card exposes top entry', () => {
  const card = formatRatingSnapshotCard({
    scope_label: 'Course',
    period_label: 'Semester',
    published_at: '2026-03-15T10:00:00Z',
    ranking_json: [{ rank: 1, full_name: 'Alice', final_score: 95 }],
  });
  assert.equal(card.top_entry.full_name, 'Alice');
  assert.equal(card.scope_label, 'Course');
});

test('attendance summary marks risky absence share', () => {
  const summary = buildAttendanceHealthSummary({
    counts: { present: 6, late: 1, absent: 3, excused: 0 },
    recentCounts: { present: 1, late: 1, absent: 2, excused: 0 },
    lastMarkedAt: '2026-03-15',
  });
  assert.equal(summary.absent_share, 30);
  assert.equal(summary.tone, 'risk');
  assert.equal(summary.status_key, 'attention');
  assert.equal(summary.recent.flagged_total, 3);
  assert.equal(summary.last_marked_at, '2026-03-15');
});

test('publish target description explains course-wide reuse', () => {
  const target = describeRatingPublishTarget({
    publishTarget: { kind: 'course' },
    scopeLabel: 'Course 2',
    periodLabel: 'Semester',
    participantsCount: 24,
    lang: 'en',
  });
  assert.equal(target.kind, 'course');
  assert.match(target.title, /full course audience/i);
  assert.match(target.note, /My Day/i);
  assert.equal(target.participants_count, 24);
});

test('relevant snapshot finder prefers exact group match before course fallback', () => {
  const exactGroup = {
    id: 11,
    course_id: 1,
    semester_id: 2,
    subject_id: 7,
    group_number: 3,
    target_kind: 'group',
    scope_type: 'group',
  };
  const courseWide = {
    id: 12,
    course_id: 1,
    semester_id: 2,
    target_kind: 'course',
    scope_type: 'course',
  };
  const result = findRelevantRatingSnapshot([courseWide, exactGroup], {
    courseId: 1,
    semesterId: 2,
    subjectId: 7,
    groupNumber: 3,
    targetKind: 'group',
  });
  assert.equal(result.id, 11);

  const fallback = findRelevantRatingSnapshot([courseWide], {
    courseId: 1,
    semesterId: 2,
    subjectId: 7,
    groupNumber: 5,
    workloadKeys: ['7|all'],
  });
  assert.equal(fallback.id, 12);
});
