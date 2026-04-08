const journalInsightHelpers = require('./journalInsights');

const VISIBLE_MESSAGE_KINDS = ['broadcast', 'announcement', 'group', 'subject', 'direct'];

function normalizeVisibleMessageKind(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return VISIBLE_MESSAGE_KINDS.includes(normalized) ? normalized : 'broadcast';
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

  if (targetAll && (subjectId > 0 || groupNumber > 0)) {
    return 'announcement';
  }
  if (targetAll) {
    return 'broadcast';
  }
  if (isDirectTarget) {
    return 'direct';
  }
  if (subjectId > 0 && groupNumber > 0) {
    return 'group';
  }
  if (subjectId > 0) {
    return 'subject';
  }
  return 'broadcast';
}

function buildVisibleMessageScopeLine(row = {}, lang = 'uk') {
  const parts = [];
  if (row && row.subject_name) {
    parts.push(String(row.subject_name).trim());
  } else if (Number(row.target_all || 0) === 1 || row.target_all === true) {
    parts.push(lang === 'en' ? 'All students' : 'Весь курс');
  }
  if (row && Number(row.group_number || 0) > 0) {
    parts.push(`${lang === 'en' ? 'Group' : 'Група'} ${Number(row.group_number)}`);
  }
  if (row && row.created_by) {
    parts.push(String(row.created_by).trim());
  }
  return parts.filter(Boolean).join(' · ');
}

function buildRatingSurfacePreview(card = null, fallbackBody = '', lang = 'uk') {
  if (!card) return fallbackBody;
  const parts = [];
  if (card.period_label) {
    parts.push(card.period_label);
  }
  if (card.top_entry && card.top_entry.full_name) {
    parts.push(`${lang === 'en' ? 'Leader' : 'Лідер'}: ${card.top_entry.full_name}`);
  } else if (card.updated_label) {
    parts.push(card.updated_label);
  }
  return parts.filter(Boolean).join(' · ') || fallbackBody;
}

function buildVisibleMessagePreview(row = {}, options = {}) {
  const staleDays = Math.max(Number(options.staleDays) || 30, 1);
  const lang = String(options.lang || 'uk').trim().toLowerCase() === 'en' ? 'en' : 'uk';
  const kind = normalizeVisibleMessageKind(classifyVisibleMessage(row));
  const body = String(row.body || '').trim();
  const fallbackBodyPreview = body.length > 180 ? `${body.slice(0, 177)}...` : body;
  const ratingSnapshotCard = row && row.rating_snapshot
    ? journalInsightHelpers.formatRatingSnapshotCard(row.rating_snapshot, lang)
    : null;
  const timestampValue = row.published_at || row.created_at || null;
  const timestamp = getVisibleMessageTimestamp(timestampValue);
  const ageDays = timestamp
    ? Math.max(0, Math.floor((Date.now() - timestamp) / (24 * 60 * 60 * 1000)))
    : null;
  const isStale = Number.isFinite(ageDays) ? ageDays >= staleDays : false;

  return {
    ...row,
    body_preview: ratingSnapshotCard
      ? buildRatingSurfacePreview(ratingSnapshotCard, fallbackBodyPreview, lang)
      : fallbackBodyPreview,
    message_title: ratingSnapshotCard
      ? (
        lang === 'en'
          ? `Published rating: ${ratingSnapshotCard.scope_label}`
          : `Опубліковано рейтинг: ${ratingSnapshotCard.scope_label}`
      )
      : '',
    message_scope_line: buildVisibleMessageScopeLine(row, lang),
    message_kind: kind,
    message_channel: 'messages',
    is_broadcast: kind !== 'direct',
    is_rating_publication: Boolean(ratingSnapshotCard),
    rating_snapshot_card: ratingSnapshotCard,
    is_fresh: !isStale,
    is_stale: isStale,
    age_days: Number.isFinite(ageDays) ? ageDays : null,
  };
}

function summarizeVisibleMessages(rows = [], options = {}) {
  const staleDays = Math.max(Number(options.staleDays) || 30, 1);
  const lang = String(options.lang || 'uk').trim().toLowerCase() === 'en' ? 'en' : 'uk';
  const items = (Array.isArray(rows) ? rows : []).map((row) => buildVisibleMessagePreview(row, { staleDays, lang }));
  const byKind = VISIBLE_MESSAGE_KINDS.reduce((summary, kind) => ({
    ...summary,
    [kind]: items.filter((item) => item.message_kind === kind).length,
  }), {});

  return {
    total: items.length,
    unread: items.filter((item) => !item.read_id).length,
    fresh: items.filter((item) => item.is_fresh).length,
    fresh_unread: items.filter((item) => item.is_fresh && !item.read_id).length,
    broadcast: Number(byKind.broadcast || 0),
    announcement: Number(byKind.announcement || 0),
    announcements: items.filter((item) => item.message_kind !== 'direct').length,
    group: Number(byKind.group || 0),
    subject: Number(byKind.subject || 0),
    direct: Number(byKind.direct || 0),
    stale: items.filter((item) => item.is_stale).length,
    latest_at: items
      .map((item) => item.published_at || item.created_at || null)
      .filter(Boolean)
      .sort()
      .pop() || null,
    by_kind: byKind,
  };
}

module.exports = {
  VISIBLE_MESSAGE_KINDS,
  buildVisibleMessagePreview,
  classifyVisibleMessage,
  normalizeVisibleMessageKind,
  summarizeVisibleMessages,
};
