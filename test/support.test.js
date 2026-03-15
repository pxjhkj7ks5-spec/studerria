const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildSupportRequestFallbackMessages,
  buildSupportRequestPreview,
  summarizeSupportRequests,
} = require('../lib/support');

test('support fallback builds user and admin messages in order', () => {
  const thread = buildSupportRequestFallbackMessages({
    id: 14,
    user_id: 9,
    user_name: 'Student',
    body: 'Need help',
    admin_note: 'Resolved',
    created_at: '2026-03-10T09:00:00Z',
    updated_at: '2026-03-10T10:00:00Z',
  });
  assert.equal(thread.length, 2);
  assert.equal(thread[0].author_role, 'user');
  assert.equal(thread[1].author_role, 'admin');
});

test('support preview prefers threaded messages and exposes latest activity', () => {
  const preview = buildSupportRequestPreview(
    { id: 2, status: 'in_progress', created_at: '2026-03-10T09:00:00Z' },
    [
      { id: 1, author_role: 'user', author_name: 'Student', body: 'First', created_at: '2026-03-10T09:00:00Z' },
      { id: 2, author_role: 'admin', author_name: 'Admin', body: 'Reply', created_at: '2026-03-10T10:00:00Z' },
    ]
  );
  assert.equal(preview.messages_count, 2);
  assert.equal(preview.last_message_preview, 'Reply');
  assert.equal(preview.last_message_at, '2026-03-10T10:00:00Z');
});

test('support summary counts open and resolved requests', () => {
  const summary = summarizeSupportRequests([
    { status: 'new', created_at: '2026-03-10T09:00:00Z' },
    { status: 'resolved', created_at: '2026-03-10T11:00:00Z' },
  ], { responseLabel: 'within 1 business day' });
  assert.equal(summary.open, 1);
  assert.equal(summary.resolved, 1);
  assert.equal(summary.response, 'within 1 business day');
});
