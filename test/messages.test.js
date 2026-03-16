const test = require('node:test');
const assert = require('node:assert/strict');

const {
  classifyVisibleMessage,
  buildVisibleMessagePreview,
  summarizeVisibleMessages,
} = require('../lib/messages');

test('classify visible messages by audience type', () => {
  assert.equal(classifyVisibleMessage({ target_all: 1 }), 'broadcast');
  assert.equal(classifyVisibleMessage({ target_all: 1, subject_id: 12, group_number: 2 }), 'announcement');
  assert.equal(classifyVisibleMessage({ subject_id: 8, group_number: 1 }), 'group');
  assert.equal(classifyVisibleMessage({ subject_id: 8 }), 'subject');
  assert.equal(classifyVisibleMessage({ is_direct_target: 1 }), 'direct');
});

test('build visible message preview marks stale items and trims preview text', () => {
  const preview = buildVisibleMessagePreview({
    body: 'A'.repeat(220),
    created_at: '2026-01-01T09:00:00Z',
    target_all: 1,
  }, { staleDays: 30 });

  assert.equal(preview.message_kind, 'broadcast');
  assert.equal(preview.is_stale, true);
  assert.equal(preview.is_fresh, false);
  assert.equal(preview.body_preview.length, 180);
});

test('summarize visible messages counts unread, fresh, and direct updates', () => {
  const summary = summarizeVisibleMessages([
    {
      id: 1,
      body: 'Broadcast',
      created_at: '2026-03-10T09:00:00Z',
      target_all: 1,
      read_id: null,
    },
    {
      id: 2,
      body: 'Direct',
      created_at: '2026-03-12T09:00:00Z',
      is_direct_target: 1,
      read_id: 22,
    },
  ], { staleDays: 30 });

  assert.equal(summary.total, 2);
  assert.equal(summary.unread, 1);
  assert.equal(summary.direct, 1);
  assert.equal(summary.announcements, 1);
});
