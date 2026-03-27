function cleanCompactText(value, maxLength = 160) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, Math.max(1, Number(maxLength) || 1));
}

function normalizeHomeworkTemplateTitleInput(rawTitle, fallbackDescription, fallbackSubjectName) {
  const explicitTitle = cleanCompactText(rawTitle, 160);
  if (explicitTitle) {
    return explicitTitle;
  }
  const fallbackLine = cleanCompactText(String(fallbackDescription || '').split('\n')[0], 160);
  if (fallbackLine) {
    return fallbackLine;
  }
  const subjectLabel = cleanCompactText(fallbackSubjectName, 120);
  if (subjectLabel) {
    return `${subjectLabel} homework`.slice(0, 160);
  }
  return 'Homework template';
}

function normalizeTemplateAssetIds(rawValue, limit = 24) {
  const values = Array.isArray(rawValue)
    ? rawValue
    : (typeof rawValue === 'string' ? rawValue.split(',') : [rawValue]);
  return Array.from(new Set(values
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value > 0)))
    .slice(0, Math.max(1, Number(limit) || 1));
}

function buildAppliedHomeworkAssetIds({ templateAssetIds = [], uploadedAssetIds = [] } = {}) {
  const ordered = [];
  const seen = new Set();
  normalizeTemplateAssetIds(templateAssetIds, 64).forEach((assetId) => {
    if (seen.has(assetId)) return;
    seen.add(assetId);
    ordered.push(assetId);
  });
  normalizeTemplateAssetIds(uploadedAssetIds, 64).forEach((assetId) => {
    if (seen.has(assetId)) return;
    seen.add(assetId);
    ordered.push(assetId);
  });
  return ordered;
}

function buildAssetDisplayName(assetRow = {}) {
  const explicitName = cleanCompactText(assetRow.name, 160);
  if (explicitName) return explicitName;
  const originalName = cleanCompactText(assetRow.original_name, 160);
  if (originalName) return originalName;
  return 'Attachment';
}

function normalizePositiveInt(value) {
  const normalized = Number(value || 0);
  return Number.isInteger(normalized) && normalized > 0 ? normalized : null;
}

function normalizeTeacherSubjectSelections(selections = []) {
  const unique = new Map();
  (Array.isArray(selections) ? selections : []).forEach((selection, index) => {
    const subjectId = normalizePositiveInt(selection && selection.subject_id);
    if (!subjectId) return;
    const groupNumber = normalizePositiveInt(selection && selection.group_number);
    const key = `${subjectId}:${groupNumber || 0}`;
    if (unique.has(key)) return;
    unique.set(key, {
      subject_id: subjectId,
      group_number: groupNumber,
      sort_order: Number(index || 0),
    });
  });
  return Array.from(unique.values());
}

async function replaceTeacherSubjectsMirror(store, userId, selections = []) {
  const normalizedUserId = normalizePositiveInt(userId);
  if (!normalizedUserId || !store || typeof store.run !== 'function') {
    return 0;
  }
  const normalizedSelections = normalizeTeacherSubjectSelections(selections);
  await store.run('DELETE FROM teacher_subjects WHERE user_id = ?', [normalizedUserId]);
  for (const selection of normalizedSelections) {
    await store.run(
      'INSERT INTO teacher_subjects (user_id, subject_id, group_number) VALUES (?, ?, ?)',
      [normalizedUserId, selection.subject_id, selection.group_number]
    );
  }
  return normalizedSelections.length;
}

async function upsertTeacherRequestStatus(store, userId, options = {}) {
  const normalizedUserId = normalizePositiveInt(userId);
  if (!normalizedUserId || !store || typeof store.get !== 'function' || typeof store.run !== 'function') {
    return 'pending';
  }
  const allowPendingReset = options.allowPendingReset === true;
  const forcedStatus = cleanCompactText(options.status, 32).toLowerCase();
  const existing = await store.get('SELECT status FROM teacher_requests WHERE user_id = ?', [normalizedUserId]);
  let nextStatus = forcedStatus || (existing ? String(existing.status || 'pending') : 'pending');
  if (!forcedStatus && nextStatus === 'rejected') {
    nextStatus = 'pending';
  }
  if (!['pending', 'approved', 'rejected'].includes(nextStatus)) {
    nextStatus = 'pending';
  }
  if (existing) {
    if (forcedStatus || nextStatus !== 'approved' || allowPendingReset) {
      await store.run(
        'UPDATE teacher_requests SET status = ?, updated_at = NOW() WHERE user_id = ?',
        [nextStatus, normalizedUserId]
      );
    } else {
      await store.run('UPDATE teacher_requests SET updated_at = NOW() WHERE user_id = ?', [normalizedUserId]);
    }
  } else {
    await store.run(
      'INSERT INTO teacher_requests (user_id, status) VALUES (?, ?)',
      [normalizedUserId, nextStatus]
    );
  }
  return nextStatus;
}

async function getTeacherRequestStatus(store, userId) {
  const normalizedUserId = normalizePositiveInt(userId);
  if (!normalizedUserId || !store || typeof store.get !== 'function') {
    return null;
  }
  const row = await store.get('SELECT status FROM teacher_requests WHERE user_id = ?', [normalizedUserId]);
  return row && row.status ? cleanCompactText(row.status, 32).toLowerCase() : null;
}

async function listTeacherRequestSummaries(store, options = {}) {
  if (!store || typeof store.all !== 'function') {
    return [];
  }
  const normalizedStatus = cleanCompactText(options.status, 32).toLowerCase();
  const params = [];
  const where = [];
  if (['pending', 'approved', 'rejected'].includes(normalizedStatus)) {
    where.push('tr.status = ?');
    params.push(normalizedStatus);
  }
  const rows = await store.all(
    `
      SELECT tr.user_id, tr.status, tr.created_at,
             u.full_name,
             COALESCE(
               array_agg(DISTINCT (s.name || ' (' || c.name || ')'))
                 FILTER (WHERE s.id IS NOT NULL),
               ARRAY[]::text[]
             ) AS subjects
      FROM teacher_requests tr
      JOIN users u ON u.id = tr.user_id
      LEFT JOIN teacher_subjects ts ON ts.user_id = tr.user_id
      LEFT JOIN subjects s ON s.id = ts.subject_id
      LEFT JOIN courses c ON c.id = s.course_id
      ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
      GROUP BY tr.user_id, tr.status, tr.created_at, u.full_name
      ORDER BY tr.created_at DESC
    `,
    params
  );
  return Array.isArray(rows) ? rows : [];
}

async function listTeacherSubjectSelections(store, userId) {
  const normalizedUserId = normalizePositiveInt(userId);
  if (!normalizedUserId || !store || typeof store.all !== 'function') {
    return [];
  }
  const rows = await store.all(
    'SELECT subject_id, group_number FROM teacher_subjects WHERE user_id = ?',
    [normalizedUserId]
  );
  return Array.isArray(rows) ? rows : [];
}

async function listTeacherSubjectMirrorRows(store, userId, options = {}) {
  const normalizedUserId = normalizePositiveInt(userId);
  const normalizedSubjectId = normalizePositiveInt(options.subjectId);
  const includeHidden = options.includeHidden === true;
  if (!normalizedUserId || !store || typeof store.all !== 'function') {
    return [];
  }
  const params = [normalizedUserId];
  const subjectFilter = normalizedSubjectId ? 'AND ts.subject_id = ?' : '';
  if (normalizedSubjectId) {
    params.push(normalizedSubjectId);
  }
  const visibilityFilter = includeHidden
    ? ''
    : "AND COALESCE(LOWER(TRIM(CAST(s.visible AS TEXT))), '1') IN ('1', 'true', 't')";
  try {
    const rows = await store.all(
      `
        SELECT DISTINCT
          ts.subject_id,
          ts.group_number,
          s.name AS subject_name,
          s.group_count,
          s.is_general,
          s.show_in_teamwork,
          scb.course_id,
          s.course_id AS owner_course_id,
          c.name AS course_name,
          s.is_shared
        FROM teacher_subjects ts
        JOIN subjects s ON s.id = ts.subject_id
        JOIN subject_course_bindings scb ON scb.subject_id = s.id
        JOIN courses c ON c.id = scb.course_id
        WHERE ts.user_id = ?
          ${subjectFilter}
          ${visibilityFilter}
        ORDER BY scb.course_id ASC, s.name ASC, ts.group_number NULLS FIRST
      `,
      params
    );
    return Array.isArray(rows) ? rows : [];
  } catch (err) {
    if (!(err && (err.code === '42P01' || err.code === '42703'))) {
      throw err;
    }
    const fallbackRows = await store.all(
      `
        SELECT DISTINCT
          ts.subject_id,
          ts.group_number,
          s.name AS subject_name,
          s.group_count,
          s.is_general,
          s.show_in_teamwork,
          s.course_id,
          s.course_id AS owner_course_id,
          c.name AS course_name,
          false AS is_shared
        FROM teacher_subjects ts
        JOIN subjects s ON s.id = ts.subject_id
        JOIN courses c ON c.id = s.course_id
        WHERE ts.user_id = ?
          ${subjectFilter}
          ${visibilityFilter}
        ORDER BY s.course_id ASC, s.name ASC, ts.group_number NULLS FIRST
      `,
      params
    );
    return Array.isArray(fallbackRows) ? fallbackRows : [];
  }
}

async function listTeacherAssignedSubjectRows(store, userId) {
  const normalizedUserId = normalizePositiveInt(userId);
  if (!normalizedUserId || !store || typeof store.all !== 'function') {
    return [];
  }
  try {
    const rows = await store.all(
      `
        SELECT
          ts.subject_id,
          COALESCE(toa.subject_offering_id, so.id) AS subject_offering_id,
          ts.group_number,
          s.name AS subject_name,
          s.group_count,
          s.is_general,
          s.show_in_teamwork,
          scb.course_id,
          s.course_id AS owner_course_id,
          c.name AS course_name,
          s.is_shared
        FROM teacher_subjects ts
        JOIN subjects s ON s.id = ts.subject_id
        JOIN subject_course_bindings scb ON scb.subject_id = s.id
        JOIN courses c ON c.id = scb.course_id
        LEFT JOIN subject_offerings so ON so.dedupe_key = CONCAT('legacy-subject:', s.id::text)
        LEFT JOIN teacher_offering_assignments toa
          ON toa.teacher_id = ts.user_id
         AND toa.subject_offering_id = so.id
        WHERE ts.user_id = ?
          AND s.visible = 1
        ORDER BY scb.course_id ASC, s.name ASC, ts.group_number NULLS FIRST
      `,
      [normalizedUserId]
    );
    return Array.isArray(rows) ? rows : [];
  } catch (err) {
    if (!(err && (err.code === '42P01' || err.code === '42703'))) {
      throw err;
    }
    const rows = await store.all(
      `
        SELECT ts.subject_id, NULL AS subject_offering_id, ts.group_number, s.name AS subject_name, s.group_count, s.is_general,
               s.show_in_teamwork,
               s.course_id, s.course_id AS owner_course_id, c.name AS course_name, false AS is_shared
        FROM teacher_subjects ts
        JOIN subjects s ON s.id = ts.subject_id
        JOIN courses c ON c.id = s.course_id
        WHERE ts.user_id = ? AND s.visible = 1
        ORDER BY c.id, s.name, ts.group_number NULLS FIRST
      `,
      [normalizedUserId]
    );
    return Array.isArray(rows) ? rows : [];
  }
}

async function hasTeacherSubjectMirrorAssignment(store, userId, subjectId) {
  const rows = await listTeacherSubjectMirrorRows(store, userId, {
    subjectId,
    includeHidden: true,
  });
  return rows.length > 0;
}

async function userHasTeacherMirrorCourseAccess(store, userId, courseId) {
  const normalizedUserId = normalizePositiveInt(userId);
  const normalizedCourseId = normalizePositiveInt(courseId);
  if (!normalizedUserId || !normalizedCourseId || !store || typeof store.get !== 'function') {
    return false;
  }
  try {
    const row = await store.get(
      `
        SELECT 1
        FROM teacher_subjects ts
        JOIN subject_course_bindings scb ON scb.subject_id = ts.subject_id
        WHERE ts.user_id = ? AND scb.course_id = ?
        LIMIT 1
      `,
      [normalizedUserId, normalizedCourseId]
    );
    return Boolean(row);
  } catch (err) {
    if (!(err && (err.code === '42P01' || err.code === '42703'))) {
      throw err;
    }
    const row = await store.get(
      `
        SELECT 1
        FROM teacher_subjects ts
        JOIN subjects s ON s.id = ts.subject_id
        WHERE ts.user_id = ? AND s.course_id = ?
        LIMIT 1
      `,
      [normalizedUserId, normalizedCourseId]
    );
    return Boolean(row);
  }
}

async function listTeacherTemplateTargetSubjects(store, userId, subjectIds = []) {
  const normalizedUserId = normalizePositiveInt(userId);
  const normalizedSubjectIds = Array.from(new Set(
    (Array.isArray(subjectIds) ? subjectIds : [subjectIds])
      .map((value) => normalizePositiveInt(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  ));
  if (!normalizedUserId || !normalizedSubjectIds.length || !store || typeof store.all !== 'function') {
    return [];
  }
  const placeholders = normalizedSubjectIds.map(() => '?').join(', ');
  const rows = await store.all(
    `
      SELECT DISTINCT
        s.id AS subject_id,
        s.course_id,
        s.name AS subject_name,
        c.name AS course_name
      FROM teacher_subjects ts
      JOIN subjects s ON s.id = ts.subject_id
      LEFT JOIN courses c ON c.id = s.course_id
      WHERE ts.user_id = ?
        AND ts.subject_id IN (${placeholders})
    `,
    [normalizedUserId, ...normalizedSubjectIds]
  );
  return Array.isArray(rows) ? rows : [];
}

module.exports = {
  normalizeHomeworkTemplateTitleInput,
  normalizeTemplateAssetIds,
  buildAppliedHomeworkAssetIds,
  buildAssetDisplayName,
  getTeacherRequestStatus,
  hasTeacherSubjectMirrorAssignment,
  listTeacherAssignedSubjectRows,
  listTeacherRequestSummaries,
  listTeacherSubjectMirrorRows,
  listTeacherSubjectSelections,
  listTeacherTemplateTargetSubjects,
  normalizeTeacherSubjectSelections,
  replaceTeacherSubjectsMirror,
  userHasTeacherMirrorCourseAccess,
  upsertTeacherRequestStatus,
};
