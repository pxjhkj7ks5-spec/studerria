const assert = require('node:assert/strict');
const test = require('node:test');

const {
  createTelegramActionTokenStore,
} = require('../lib/telegramActionTokens');

test('telegram action token can be consumed only once', () => {
  let currentTime = 1000;
  const store = createTelegramActionTokenStore({
    now: () => currentTime,
    tokenFactory: () => 'fixed-token-000000000000',
  });
  const payload = { flow: 'add_commit', weekNumber: 4 };
  const token = store.createActionToken(payload);

  assert.equal(token, 'stb:fixedtoken000000000000');
  assert.deepEqual(store.getActionPayload(token), payload);
  assert.deepEqual(store.consumeActionPayload(token), payload);
  assert.equal(store.getActionPayload(token), null);
  assert.equal(store.consumeActionPayload(token), null);
  assert.equal(store.wasActionConsumed(token), true);

  currentTime += 2 * 60 * 1000 + 1;
  assert.equal(store.wasActionConsumed(token), false);
});

test('telegram action token expires before it can be consumed', () => {
  let currentTime = 5000;
  const store = createTelegramActionTokenStore({
    actionTtlMs: 50,
    now: () => currentTime,
    tokenFactory: () => 'short-lived-token',
  });
  const token = store.createActionToken({ flow: 'add_commit' });

  currentTime += 51;

  assert.equal(store.getActionPayload(token), null);
  assert.equal(store.consumeActionPayload(token), null);
  assert.equal(store.wasActionConsumed(token), false);
});
