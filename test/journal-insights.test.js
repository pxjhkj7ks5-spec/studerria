const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildRatingSnapshotPayload,
  formatRatingSnapshotCard,
  buildAttendanceHealthSummary,
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
  });
  assert.equal(summary.absent_share, 30);
  assert.equal(summary.tone, 'risk');
});
