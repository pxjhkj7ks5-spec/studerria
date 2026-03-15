const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildRoomLabel,
  normalizeRoomInput,
  buildRoomConflictReport,
} = require('../lib/rooms');

test('room label combines building and label', () => {
  assert.equal(buildRoomLabel({ building: 'A', label: '204' }), 'A · 204');
});

test('room input requires a course and room label or code', () => {
  assert.equal(normalizeRoomInput({ label: '' }).ok, false);
  assert.equal(normalizeRoomInput({ course_id: 2, label: '204' }).ok, true);
});

test('room conflict report detects draft duplicates and occupied rooms', () => {
  const conflicts = buildRoomConflictReport({
    assignments: [
      { subject_id: 1, group_number: 1, date: '2026-03-20', class_number: 2, room_id: 7 },
      { subject_id: 2, group_number: 1, date: '2026-03-20', class_number: 2, room_id: 7 },
    ],
    busyRows: [],
    roomsById: new Map([
      [7, { id: 7, building: 'A', label: '204', room_label: 'A · 204' }],
    ]),
    selectedCourseId: 1,
  });
  assert.equal(conflicts.length, 1);
  const occupied = buildRoomConflictReport({
    assignments: [
      { subject_id: 1, group_number: 1, date: '2026-03-21', class_number: 3, room_id: 8 },
    ],
    busyRows: [
      { source_ref: 'schedule:1', course_id: 2, subject_id: 9, group_number: 1, date: '2026-03-21', class_number: 3, room_id: 8 },
    ],
    roomsById: new Map([[8, { id: 8, building: 'B', label: '17', room_label: 'B · 17' }]]),
    selectedCourseId: 1,
  });
  assert.equal(occupied.length, 1);
  assert.equal(occupied[0].type, 'occupied');
});
