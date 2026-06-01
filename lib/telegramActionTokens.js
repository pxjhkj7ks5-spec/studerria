const { randomUUID } = require('crypto');

const DEFAULT_ACTION_TTL_MS = 10 * 60 * 1000;
const DEFAULT_CONSUMED_ACTION_TTL_MS = 2 * 60 * 1000;
const DEFAULT_PREFIX = 'stb:';

function createDefaultToken() {
  return randomUUID().replace(/-/g, '').slice(0, 24);
}

function normalizeCallbackData(callbackData = '', prefix = DEFAULT_PREFIX) {
  const raw = String(callbackData || '').trim();
  if (!raw.startsWith(prefix)) return '';
  return raw.slice(prefix.length);
}

function createTelegramActionTokenStore(options = {}) {
  const actionTtlMs = Number(options.actionTtlMs || DEFAULT_ACTION_TTL_MS);
  const consumedActionTtlMs = Number(options.consumedActionTtlMs || DEFAULT_CONSUMED_ACTION_TTL_MS);
  const prefix = String(options.prefix || DEFAULT_PREFIX);
  const now = typeof options.now === 'function' ? options.now : () => Date.now();
  const tokenFactory = typeof options.tokenFactory === 'function' ? options.tokenFactory : createDefaultToken;
  const actionStore = new Map();
  const consumedActionStore = new Map();

  function prune(currentTime = now()) {
    for (const [token, item] of actionStore.entries()) {
      if (!item || Number(item.expiresAt || 0) <= currentTime) {
        actionStore.delete(token);
      }
    }
    for (const [token, item] of consumedActionStore.entries()) {
      if (!item || Number(item.expiresAt || 0) <= currentTime) {
        consumedActionStore.delete(token);
      }
    }
  }

  function createActionToken(payload = {}) {
    prune();
    const token = String(tokenFactory() || createDefaultToken()).replace(/-/g, '').slice(0, 24);
    actionStore.set(token, {
      payload,
      expiresAt: now() + actionTtlMs,
    });
    return `${prefix}${token}`;
  }

  function getActionPayload(callbackData = '') {
    const token = normalizeCallbackData(callbackData, prefix);
    if (!token) return null;
    prune();
    const item = actionStore.get(token);
    return item && item.payload ? item.payload : null;
  }

  function consumeActionPayload(callbackData = '') {
    const token = normalizeCallbackData(callbackData, prefix);
    if (!token) return null;
    prune();
    const item = actionStore.get(token);
    if (!item || !item.payload) return null;
    actionStore.delete(token);
    consumedActionStore.set(token, {
      expiresAt: now() + consumedActionTtlMs,
    });
    return item.payload;
  }

  function wasActionConsumed(callbackData = '') {
    const token = normalizeCallbackData(callbackData, prefix);
    if (!token) return false;
    prune();
    return consumedActionStore.has(token);
  }

  return {
    createActionToken,
    getActionPayload,
    consumeActionPayload,
    wasActionConsumed,
    prune,
  };
}

const defaultStore = createTelegramActionTokenStore();

module.exports = {
  DEFAULT_ACTION_TTL_MS,
  DEFAULT_CONSUMED_ACTION_TTL_MS,
  createTelegramActionTokenStore,
  createStuderriaTelegramActionToken: defaultStore.createActionToken,
  getStuderriaTelegramActionPayload: defaultStore.getActionPayload,
  consumeStuderriaTelegramActionPayload: defaultStore.consumeActionPayload,
  wasStuderriaTelegramActionConsumed: defaultStore.wasActionConsumed,
};
