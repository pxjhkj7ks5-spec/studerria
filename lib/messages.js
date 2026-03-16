const VISIBLE_MESSAGE_KINDS = ['broadcast', 'announcement', 'group', 'subject', 'direct'];

function normalizeVisibleMessageKind(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return VISIBLE_MESSAGE_KINDS.includes(normalized) ? normalized : 'direct';
}

function getVisibleMessageTimestamp(value) {
  const ts = new Date(value || 0).getTime();
  return Number.isFinite(ts) ? ts : 0;
}

function classifyVisibleMessage(row = {}) {
  const targetAll = Number(row.target_all || 0) === 1 || row.target_all === true;
  const subjectId = Number(row.subject_id || 0);
  const groupNumber = Number(row.group_number || 0);
  const isDirectTarget = Number(row.is_direct_target || 0) === 1 || row.is_direct_target === true;

  if (isDirectTarget && !targetAll && subjectId < 1 && groupNumber < 1) {
    return 'direct';
  }
  if (targetAll && subjectId < 1 && groupNumber < 1) {
    return 'broadcast';
  }
  if (targetAll) {
    return 'announcement';
  }
  if (subjectId > 0 && groupNumber > 0) {
    return 'group';
  }
  if (subjectId > 0) {
    return 'subject';
  }
  if (isDirectTarget) {
    return 'direct';
  }
  return 'announcement';
}

function buildVisibleMessagePreview(row = {}, options = {}) {
  const staleDays = Math.max(Number(options.staleDays) || 30, 1);
  const kind = normalizeVisibleMessageKind(classifyVisibleMessage(row));
  const body = String(row.body || '').trim();
  const timestampValue = row.published_at || row.created_at || null;
  const timestamp = getVisibleMessageTimestamp(timestampValue);
  const ageDays = timestamp
    ? Math.max(0, Math.floor((Date.now() - timestamp) / (24 * 60 * 60 * 1000)))
    : null;
  const isStale = Number.isFinite(ageDays) ? ageDays >= staleDays : false;

  return {
    ...row,
    body_preview: body.length > 180 ? `${body.slice(0, 177)}...` : body,
    message_kind: kind,
    is_broadcast: kind !== 'direct',
    is_fresh: !isStale,
    is_stale: isStale,
    age_days: Number.isFinite(ageDays) ? ageDays : null,
  };
}

function summarizeVisibleMessages(rows = [], options = {}) {
  const staleDays = Math.max(Number(options.staleDays) || 30, 1);
  const items = (Array.isArray(rows) ? rows : []).map((row) => buildVisibleMessagePreview(row, { staleDays }));

  return {
    total: items.length,
    unread: items.filter((item) => !item.read_id).length,
    fresh: items.filter((item) => item.is_fresh).length,
    fresh_unread: items.filter((item) => item.is_fresh && !item.read_id).length,
    announcements: items.filter((item) => item.is_broadcast).length,
    direct: items.filter((item) => item.message_kind === 'direct').length,
    stale: items.filter((item) => item.is_stale).length,
    latest_at: items
      .map((item) => item.published_at || item.created_at || null)
      .filter(Boolean)
      .sort()
      .pop() || null,
  };
}

module.exports = {
  VISIBLE_MESSAGE_KINDS,
  normalizeVisibleMessageKind,
  classifyVisibleMessage,
  buildVisibleMessagePreview,
  summarizeVisibleMessages,
};
