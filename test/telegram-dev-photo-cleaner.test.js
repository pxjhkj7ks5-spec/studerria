const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  handleStuderriaTelegramDevPhotoCleanerMessage,
} = require('../lib/studerriaTelegramPhotoCleaner');

function createPhotoMessage(chatId = '-100123') {
  return {
    message_id: 55,
    chat: { id: chatId, type: 'supergroup' },
    photo: [
      { file_id: 'small-file', width: 320, height: 240, file_size: 1000 },
      { file_id: 'large-file', width: 1600, height: 1200, file_size: 9000 },
    ],
  };
}

function createDeps(overrides = {}) {
  const calls = [];
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'studerria-cleaner-test-'));
  const deps = {
    env: {
      STUDERRIA_TG_DEV_PHOTO_CLEANER_ENABLED: 'true',
      STUDERRIA_TG_DEV_PHOTO_CLEANER_CHAT_IDS: '-100123',
    },
    tmpRoot,
    logger: {
      log: (...args) => calls.push(['log', ...args]),
      warn: (...args) => calls.push(['warn', ...args]),
    },
    getBotToken: () => 'test-token',
    callBotApi: async (method, payload) => {
      calls.push(['callBotApi', method, payload]);
      assert.equal(method, 'getFile');
      assert.equal(payload.file_id, 'large-file');
      return { file_path: 'photos/source.jpg' };
    },
    fetch: async (url) => {
      calls.push(['fetch', url.includes('test-token')]);
      return {
        ok: true,
        arrayBuffer: async () => Uint8Array.from([1, 2, 3, 4]).buffer,
      };
    },
    cleanImageMetadata: async (buffer, media) => {
      calls.push(['clean', Buffer.isBuffer(buffer), media.imageType.extension]);
      return Buffer.from([9, 8, 7]);
    },
    sendPhoto: async (chatId, filePath, options) => {
      calls.push(['sendPhoto', chatId, fs.existsSync(filePath), options.filename]);
      return { message_id: 99 };
    },
    sendDocument: async () => {
      calls.push(['sendDocument']);
      return { message_id: 100 };
    },
    deleteMessage: async (chatId, messageId, label) => {
      calls.push(['deleteMessage', chatId, messageId, label]);
      return true;
    },
    getMessageThreadId: () => null,
  };
  return {
    calls,
    deps: { ...deps, ...overrides },
    cleanup: () => fs.rmSync(tmpRoot, { recursive: true, force: true }),
  };
}

test('telegram dev photo cleaner ignores photos when feature is disabled', async () => {
  const { calls, deps, cleanup } = createDeps({
    env: {
      STUDERRIA_TG_DEV_PHOTO_CLEANER_ENABLED: 'false',
      STUDERRIA_TG_DEV_PHOTO_CLEANER_CHAT_IDS: '-100123',
    },
  });
  try {
    const handled = await handleStuderriaTelegramDevPhotoCleanerMessage(createPhotoMessage(), deps);
    assert.equal(handled, false);
    assert.deepEqual(calls.map((entry) => entry[0]), ['warn']);
    assert.equal(calls[0][2].reason, 'disabled');
  } finally {
    cleanup();
  }
});

test('telegram dev photo cleaner ignores photos from chats outside allowlist', async () => {
  const { calls, deps, cleanup } = createDeps();
  try {
    const handled = await handleStuderriaTelegramDevPhotoCleanerMessage(createPhotoMessage('-100999'), deps);
    assert.equal(handled, false);
    assert.deepEqual(calls.map((entry) => entry[0]), ['warn']);
    assert.equal(calls[0][2].reason, 'not_allowed_chat');
  } finally {
    cleanup();
  }
});

test('telegram dev photo cleaner downloads, cleans, sends, then deletes allowed photos', async () => {
  const { calls, deps, cleanup } = createDeps();
  try {
    const handled = await handleStuderriaTelegramDevPhotoCleanerMessage(createPhotoMessage(), deps);
    assert.equal(handled, true);
    assert.deepEqual(
      calls.map((entry) => entry[0]),
      ['callBotApi', 'fetch', 'clean', 'sendPhoto', 'deleteMessage', 'log']
    );
    assert.deepEqual(calls[2], ['clean', true, 'jpg']);
    assert.deepEqual(calls[3], ['sendPhoto', '-100123', true, 'cleaned.jpg']);
    assert.deepEqual(calls[4], ['deleteMessage', '-100123', 55, 'dev photo cleaner original']);
    assert.equal(calls[5][2].reason, null);
  } finally {
    cleanup();
  }
});

test('telegram dev photo cleaner does not delete the original when send fails', async () => {
  const { calls, deps, cleanup } = createDeps({
    sendPhoto: async () => {
      calls.push(['sendPhoto']);
      throw new Error('send_failed');
    },
  });
  try {
    const handled = await handleStuderriaTelegramDevPhotoCleanerMessage(createPhotoMessage(), deps);
    assert.equal(handled, true);
    assert.ok(calls.some((entry) => entry[0] === 'sendPhoto'));
    assert.ok(!calls.some((entry) => entry[0] === 'deleteMessage'));
    const lastCall = calls[calls.length - 1];
    assert.equal(lastCall[0], 'warn');
    assert.equal(lastCall[2].reason, 'send_failed');
  } finally {
    cleanup();
  }
});
