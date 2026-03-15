const SUPPORT_REQUEST_CATEGORIES = ['account', 'schedule', 'journal', 'subjects', 'teamwork', 'other'];
const SUPPORT_REQUEST_STATUSES = ['new', 'in_progress', 'resolved'];
const SUPPORT_REQUEST_MESSAGE_ROLES = ['user', 'admin'];

function normalizeSupportRequestCategory(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return SUPPORT_REQUEST_CATEGORIES.includes(normalized) ? normalized : 'other';
}

function normalizeSupportRequestStatus(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return SUPPORT_REQUEST_STATUSES.includes(normalized) ? normalized : 'new';
}

function normalizeSupportRequestMessageRole(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return SUPPORT_REQUEST_MESSAGE_ROLES.includes(normalized) ? normalized : 'user';
}

function buildSupportRequestFallbackMessages(requestRow = {}) {
  const messages = [];
  const requestId = Number(requestRow.id || 0);
  const userBody = String(requestRow.body || '').trim();
  if (userBody) {
    messages.push({
      id: requestId ? `request-${requestId}-user` : 'request-user',
      request_id: requestId || null,
      author_role: 'user',
      author_user_id: Number.isFinite(Number(requestRow.user_id)) ? Number(requestRow.user_id) : null,
      author_name: String(requestRow.user_name || '').trim() || 'User',
      body: userBody,
      created_at: requestRow.created_at || null,
    });
  }
  const adminBody = String(requestRow.admin_note || '').trim();
  if (adminBody) {
    messages.push({
      id: requestId ? `request-${requestId}-admin` : 'request-admin',
      request_id: requestId || null,
      author_role: 'admin',
      author_user_id: Number.isFinite(Number(requestRow.resolved_by)) ? Number(requestRow.resolved_by) : null,
      author_name: String(requestRow.resolved_by_name || '').trim() || 'Admin',
      body: adminBody,
      created_at: requestRow.resolved_at || requestRow.updated_at || requestRow.created_at || null,
    });
  }
  return messages;
}

function ensureSupportRequestThread(requestRow = {}, messages = []) {
  const normalizedMessages = Array.isArray(messages) ? messages.filter(Boolean) : [];
  const thread = normalizedMessages.length ? normalizedMessages : buildSupportRequestFallbackMessages(requestRow);
  return thread
    .map((message) => ({
      ...message,
      author_role: normalizeSupportRequestMessageRole(message.author_role),
      author_name: String(message.author_name || '').trim()
        || (normalizeSupportRequestMessageRole(message.author_role) === 'admin' ? 'Admin' : 'User'),
      body: String(message.body || '').trim(),
    }))
    .filter((message) => message.body)
    .sort((a, b) => {
      const aTime = new Date(a.created_at || 0).getTime();
      const bTime = new Date(b.created_at || 0).getTime();
      if (Number.isFinite(aTime) && Number.isFinite(bTime) && aTime !== bTime) {
        return aTime - bTime;
      }
      return String(a.id || '').localeCompare(String(b.id || ''));
    });
}

function buildSupportRequestPreview(requestRow = {}, messages = []) {
  const thread = ensureSupportRequestThread(requestRow, messages);
  const lastMessage = thread.length ? thread[thread.length - 1] : null;
  return {
    ...requestRow,
    messages: thread,
    messages_count: thread.length,
    last_message_preview: lastMessage ? String(lastMessage.body || '').slice(0, 180) : '',
    last_message_at: lastMessage ? (lastMessage.created_at || requestRow.updated_at || requestRow.created_at || null) : null,
    needs_reply: normalizeSupportRequestStatus(requestRow.status) !== 'resolved',
  };
}

function summarizeSupportRequests(requestRows = [], options = {}) {
  const rows = Array.isArray(requestRows) ? requestRows : [];
  const responseLabel = String(options.responseLabel || '').trim();
  const open = rows.filter((row) => normalizeSupportRequestStatus(row.status) !== 'resolved').length;
  const resolved = rows.filter((row) => normalizeSupportRequestStatus(row.status) === 'resolved').length;
  const latest = rows
    .map((row) => row.last_message_at || row.updated_at || row.created_at || null)
    .filter(Boolean)
    .sort()
    .pop() || null;
  return {
    open,
    resolved,
    total: rows.length,
    latest_activity_at: latest,
    response: responseLabel,
  };
}

module.exports = {
  SUPPORT_REQUEST_CATEGORIES,
  SUPPORT_REQUEST_STATUSES,
  SUPPORT_REQUEST_MESSAGE_ROLES,
  normalizeSupportRequestCategory,
  normalizeSupportRequestStatus,
  normalizeSupportRequestMessageRole,
  buildSupportRequestFallbackMessages,
  ensureSupportRequestThread,
  buildSupportRequestPreview,
  summarizeSupportRequests,
};
