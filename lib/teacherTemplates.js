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

module.exports = {
  normalizeHomeworkTemplateTitleInput,
  normalizeTemplateAssetIds,
  buildAppliedHomeworkAssetIds,
  buildAssetDisplayName,
  normalizeTeacherSubjectSelections,
  replaceTeacherSubjectsMirror,
  upsertTeacherRequestStatus,
};
