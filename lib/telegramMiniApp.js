const { createHmac, timingSafeEqual } = require('crypto');

function hmacSha256(key, value) {
  return createHmac('sha256', key).update(value).digest();
}

function buildDataCheckString(initData) {
  const params = new URLSearchParams(String(initData || ''));
  const rows = [];
  params.forEach((value, key) => {
    if (key !== 'hash') {
      rows.push(`${key}=${value}`);
    }
  });
  return rows.sort().join('\n');
}

function validateTelegramInitData(initData, options = {}) {
  const botToken = String(options.botToken || '').trim();
  if (!botToken) {
    throw new Error('missing_bot_token');
  }
  const params = new URLSearchParams(String(initData || ''));
  const receivedHash = params.get('hash') || '';
  if (!receivedHash) {
    throw new Error('missing_hash');
  }

  const dataCheckString = buildDataCheckString(initData);
  const secretKey = hmacSha256('WebAppData', botToken);
  const expectedHash = createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  const expected = Buffer.from(expectedHash, 'hex');
  const received = Buffer.from(receivedHash, 'hex');
  if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
    throw new Error('invalid_hash');
  }

  const authDate = Number(params.get('auth_date') || 0);
  if (!Number.isFinite(authDate) || authDate <= 0) {
    throw new Error('missing_auth_date');
  }
  const maxAgeSeconds = Number(options.maxAgeSeconds || 86400);
  const nowSeconds = Number(options.nowSeconds || Math.floor(Date.now() / 1000));
  if (maxAgeSeconds > 0 && nowSeconds - authDate > maxAgeSeconds) {
    throw new Error('expired_init_data');
  }

  const rawUser = params.get('user') || '';
  if (!rawUser) {
    throw new Error('missing_user');
  }
  let user = null;
  try {
    user = JSON.parse(rawUser);
  } catch (_err) {
    throw new Error('invalid_user');
  }
  if (!user || String(user.id || '').trim() === '') {
    throw new Error('invalid_user');
  }

  return {
    user: normalizeTelegramUser(user),
    authDate,
    queryId: params.get('query_id') || '',
    startParam: params.get('start_param') || '',
  };
}

function normalizeTelegramUser(user = {}) {
  return {
    id: String(user.id || '').trim(),
    first_name: String(user.first_name || '').trim().slice(0, 120),
    last_name: String(user.last_name || '').trim().slice(0, 120),
    username: String(user.username || '').trim().slice(0, 120),
    language_code: String(user.language_code || '').trim().slice(0, 20),
    photo_url: String(user.photo_url || '').trim().slice(0, 600),
  };
}

function buildTelegramDisplayName(user = {}) {
  return [user.first_name, user.last_name]
    .map((part) => String(part || '').trim())
    .filter(Boolean)
    .join(' ')
    || (user.username ? `@${user.username}` : '');
}

function signTelegramInitDataForTest(fields, botToken) {
  const params = new URLSearchParams(fields || {});
  const dataCheckString = buildDataCheckString(params.toString());
  const secretKey = hmacSha256('WebAppData', String(botToken || ''));
  const hash = createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
  params.set('hash', hash);
  return params.toString();
}

module.exports = {
  buildDataCheckString,
  buildTelegramDisplayName,
  normalizeTelegramUser,
  signTelegramInitDataForTest,
  validateTelegramInitData,
};
