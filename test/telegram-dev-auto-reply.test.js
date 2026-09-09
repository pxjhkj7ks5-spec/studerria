const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  createStuderriaTelegramDevAutoReplyStore,
  parseStuderriaTelegramDevAutoReplyArgs,
  shouldSendStuderriaTelegramDevAutoReply,
} = require('../lib/studerriaTelegramDevAutoReply');

test('dev auto reply command parser supports setup, toggles and status', () => {
  assert.deepEqual(parseStuderriaTelegramDevAutoReplyArgs(''), { action: 'status' });
  assert.deepEqual(parseStuderriaTelegramDevAutoReplyArgs('status'), { action: 'status' });
  assert.deepEqual(parseStuderriaTelegramDevAutoReplyArgs('on'), { action: 'on' });
  assert.deepEqual(parseStuderriaTelegramDevAutoReplyArgs('off'), { action: 'off' });
  assert.deepEqual(parseStuderriaTelegramDevAutoReplyArgs('clear'), { action: 'clear' });
  assert.deepEqual(parseStuderriaTelegramDevAutoReplyArgs('set @Some_User оце моя фраза'), {
    action: 'set', targetTelegramId: '', targetUsername: 'some_user', replyText: 'оце моя фраза',
  });
  assert.deepEqual(parseStuderriaTelegramDevAutoReplyArgs('set 123456789 hello there'), {
    action: 'set', targetTelegramId: '123456789', targetUsername: '', replyText: 'hello there',
  });
  assert.equal(parseStuderriaTelegramDevAutoReplyArgs('set @user'), null);
  assert.equal(parseStuderriaTelegramDevAutoReplyArgs('on extra'), null);
});

test('dev auto reply matches only the configured human in groups', () => {
  const rule = { enabled: true, targetTelegramId: '123', targetUsername: 'old_name', replyText: 'hey' };
  assert.equal(shouldSendStuderriaTelegramDevAutoReply({ chat: { type: 'group' }, from: { id: 123 } }, rule), true);
  assert.equal(shouldSendStuderriaTelegramDevAutoReply({ chat: { type: 'supergroup' }, from: { id: 123 } }, rule), true);
  assert.equal(shouldSendStuderriaTelegramDevAutoReply({ chat: { type: 'private' }, from: { id: 123 } }, rule), false);
  assert.equal(shouldSendStuderriaTelegramDevAutoReply({ chat: { type: 'group' }, from: { id: 124 } }, rule), false);
  assert.equal(shouldSendStuderriaTelegramDevAutoReply({ chat: { type: 'group' }, from: { id: 123, is_bot: true } }, rule), false);
  assert.equal(shouldSendStuderriaTelegramDevAutoReply(
    { chat: { type: 'group' }, from: { id: 999, username: 'Some_User' } },
    { enabled: true, targetUsername: 'some_user', replyText: 'hey' }
  ), true);
  assert.equal(shouldSendStuderriaTelegramDevAutoReply(
    { chat: { type: 'group' }, from: { id: 123 } },
    { ...rule, enabled: false }
  ), false);
});

test('dev auto reply store persists setup and toggles', async () => {
  let row = null;
  const db = {
    get: async () => row,
    run: async (sql, params = []) => {
      if (/INSERT INTO/.test(sql)) {
        row = { enabled: true, target_telegram_id: params[0], target_username: params[1], reply_text: params[2], updated_by_telegram_id: params[3] };
      } else if (/UPDATE/.test(sql) && row) {
        row.enabled = params[0];
        row.updated_by_telegram_id = params[1];
      } else if (/DELETE/.test(sql)) {
        row = null;
      }
    },
  };
  const store = createStuderriaTelegramDevAutoReplyStore(db);
  assert.equal(await store.getRule(), null);
  assert.deepEqual(await store.setRule({ targetUsername: '@Test_User', replyText: 'Фраза' }, '777'), {
    enabled: true, targetTelegramId: '', targetUsername: 'test_user', replyText: 'Фраза', updatedByTelegramId: '777', updatedAt: null,
  });
  assert.equal((await store.setEnabled(false, '777')).enabled, false);
  await store.clear();
  assert.equal(await store.getRule(), null);
});

test('app wires the dev command before ordinary group reactions', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  assert.match(source, /command: 'devreply'/);
  assert.match(source, /handleStuderriaTelegramDevAutoReplyCommand/);
  assert.match(source, /handleStuderriaTelegramDevAutoReplyMessage/);
  assert.ok(source.indexOf('handleStuderriaTelegramDevAutoReplyCommand(message, parsedCommand)')
    < source.indexOf('handleStuderriaTelegramDevAutoReplyMessage(message)'));
});
