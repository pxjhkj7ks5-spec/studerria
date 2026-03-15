const ROOM_TYPES = ['classroom', 'lab', 'hall', 'office', 'online', 'other'];

function cleanCompactText(value, maxLength = 160) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, Math.max(1, Number(maxLength) || 1));
}

function normalizeRoomType(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return ROOM_TYPES.includes(normalized) ? normalized : 'classroom';
}

function normalizeRoomCampus(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'munich') return 'munich';
  if (normalized === 'kyiv') return 'kyiv';
  return 'kyiv';
}

function buildRoomLabel(roomRow = {}) {
  const label = cleanCompactText(roomRow.label, 120);
  const code = cleanCompactText(roomRow.code, 60);
  const building = cleanCompactText(roomRow.building, 80);
  const main = label || code || 'Room';
  return [building, main].filter(Boolean).join(' · ');
}

function normalizeRoomRecord(roomRow = {}) {
  const id = Number(roomRow.id || 0);
  const courseId = Number(roomRow.course_id || 0);
  const capacity = Number(roomRow.capacity || 0);
  const isActive = roomRow.is_active === true || Number(roomRow.is_active) === 1;
  return {
    id: Number.isInteger(id) && id > 0 ? id : null,
    course_id: Number.isInteger(courseId) && courseId > 0 ? courseId : null,
    campus: normalizeRoomCampus(roomRow.campus),
    building: cleanCompactText(roomRow.building, 80),
    code: cleanCompactText(roomRow.code, 60),
    label: cleanCompactText(roomRow.label, 120),
    room_type: normalizeRoomType(roomRow.room_type),
    capacity: Number.isInteger(capacity) && capacity > 0 ? capacity : null,
    notes: cleanCompactText(roomRow.notes, 500),
    is_active: isActive ? 1 : 0,
    room_label: buildRoomLabel(roomRow),
  };
}

function normalizeRoomInput(body = {}, options = {}) {
  const courseId = Number(body.course_id || options.courseId || 0);
  const room = normalizeRoomRecord({
    course_id: courseId,
    campus: body.campus || options.campus || 'kyiv',
    building: body.building,
    code: body.code,
    label: body.label,
    room_type: body.room_type,
    capacity: body.capacity,
    notes: body.notes,
    is_active: Object.prototype.hasOwnProperty.call(body, 'is_active') ? body.is_active : 1,
  });
  if (!Number.isInteger(room.course_id) || room.course_id < 1) {
    return { ok: false, error: 'Course is required' };
  }
  if (!room.label && !room.code) {
    return { ok: false, error: 'Room label or code is required' };
  }
  return { ok: true, value: room };
}

function buildRoomConflictReport({
  assignments = [],
  busyRows = [],
  roomsById = new Map(),
  selectedCourseId = null,
} = {}) {
  const conflicts = [];
  const busyBySlot = new Map();
  const draftBySlot = new Map();
  const conflictDedup = new Set();

  const pushConflict = (payload) => {
    const key = [
      String(payload.resource_kind || 'room'),
      String(payload.type || ''),
      Number(payload.room_id || 0),
      String(payload.date || ''),
      Number(payload.class_number || 0),
      String(payload.source_ref || ''),
      String(payload.other_ref || ''),
    ].join('|');
    if (conflictDedup.has(key)) return;
    conflictDedup.add(key);
    conflicts.push(payload);
  };

  (Array.isArray(busyRows) ? busyRows : []).forEach((row) => {
    const roomId = Number(row.room_id || 0);
    const classNumber = Number(row.class_number || 0);
    const date = String(row.date || '').slice(0, 10);
    if (!Number.isInteger(roomId) || roomId < 1 || !date || !Number.isInteger(classNumber) || classNumber < 1) {
      return;
    }
    const key = `${roomId}|${date}|${classNumber}`;
    if (!busyBySlot.has(key)) busyBySlot.set(key, []);
    busyBySlot.get(key).push(row);
  });

  (Array.isArray(assignments) ? assignments : []).forEach((row) => {
    const roomId = Number(row.room_id || 0);
    const classNumber = Number(row.class_number || 0);
    const date = String(row.date || '').slice(0, 10);
    if (!Number.isInteger(roomId) || roomId < 1 || !date || !Number.isInteger(classNumber) || classNumber < 1) {
      return;
    }
    const key = `${roomId}|${date}|${classNumber}`;
    const room = roomsById && typeof roomsById.get === 'function' ? roomsById.get(roomId) : null;
    if (!draftBySlot.has(key)) draftBySlot.set(key, []);
    const sameDraftRows = draftBySlot.get(key);
    sameDraftRows.forEach((otherRow) => {
      pushConflict({
        resource_kind: 'room',
        type: 'draft',
        room_id: roomId,
        room_label: room ? room.room_label || buildRoomLabel(room) : `Room ${roomId}`,
        date,
        class_number: classNumber,
        source_ref: `${row.subject_id}|${row.group_number || 'all'}`,
        other_ref: `${otherRow.subject_id}|${otherRow.group_number || 'all'}`,
        details: {
          current: row,
          other: otherRow,
        },
      });
    });
    sameDraftRows.push(row);

    const busyMatches = busyBySlot.get(key) || [];
    busyMatches.forEach((busy) => {
      const sameTarget = Number(busy.course_id || 0) === Number(selectedCourseId || 0)
        && Number(busy.subject_id || 0) === Number(row.subject_id || 0)
        && Number(busy.group_number || 0) === Number(row.group_number || 0);
      if (sameTarget) return;
      pushConflict({
        resource_kind: 'room',
        type: 'occupied',
        room_id: roomId,
        room_label: room ? room.room_label || buildRoomLabel(room) : `Room ${roomId}`,
        date,
        class_number: classNumber,
        source_ref: String(busy.source_ref || ''),
        other_ref: `${row.subject_id}|${row.group_number || 'all'}`,
        details: {
          current: row,
          busy,
        },
      });
    });
  });

  return conflicts.sort((a, b) => {
    const byDate = String(a.date || '').localeCompare(String(b.date || ''));
    if (byDate !== 0) return byDate;
    const byClass = Number(a.class_number || 0) - Number(b.class_number || 0);
    if (byClass !== 0) return byClass;
    return String(a.room_label || '').localeCompare(String(b.room_label || ''), 'uk');
  });
}

module.exports = {
  ROOM_TYPES,
  normalizeRoomType,
  normalizeRoomCampus,
  buildRoomLabel,
  normalizeRoomRecord,
  normalizeRoomInput,
  buildRoomConflictReport,
};
