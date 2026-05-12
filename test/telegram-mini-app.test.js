const assert = require('node:assert/strict');
const test = require('node:test');

const {
  buildDataCheckString,
  signTelegramInitDataForTest,
  validateTelegramInitData,
} = require('../lib/telegramMiniApp');

test('buildDataCheckString sorts init data and ignores hash', () => {
  const actual = buildDataCheckString('b=2&hash=skip&a=1');
  assert.equal(actual, 'a=1\nb=2');
});

test('validateTelegramInitData accepts signed init data', () => {
  const botToken = '123456:test-token';
  const initData = signTelegramInitDataForTest({
    auth_date: '2000',
    query_id: 'query-1',
    user: JSON.stringify({ id: 42, first_name: 'Ada', username: 'ada' }),
  }, botToken);

  const result = validateTelegramInitData(initData, {
    botToken,
    nowSeconds: 2100,
  });

  assert.equal(result.user.id, '42');
  assert.equal(result.user.first_name, 'Ada');
  assert.equal(result.queryId, 'query-1');
});

test('validateTelegramInitData rejects tampered init data', () => {
  const botToken = '123456:test-token';
  const initData = signTelegramInitDataForTest({
    auth_date: '2000',
    user: JSON.stringify({ id: 42, first_name: 'Ada' }),
  }, botToken);

  assert.throws(
    () => validateTelegramInitData(`${initData}&first_name=changed`, {
      botToken,
      nowSeconds: 2100,
    }),
    /invalid_hash/
  );
});

test('validateTelegramInitData rejects expired init data', () => {
  const botToken = '123456:test-token';
  const initData = signTelegramInitDataForTest({
    auth_date: '1000',
    user: JSON.stringify({ id: 42 }),
  }, botToken);

  assert.throws(
    () => validateTelegramInitData(initData, {
      botToken,
      nowSeconds: 2000,
      maxAgeSeconds: 60,
    }),
    /expired_init_data/
  );
});
