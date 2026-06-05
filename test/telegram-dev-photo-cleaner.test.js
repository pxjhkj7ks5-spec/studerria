const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  getImageTypeFromBuffer,
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

function createImageDocumentMessage(chatId = '-100123') {
  return createDocumentMessage({
    chatId,
    messageId: 56,
    fileId: 'document-file',
    fileName: 'photo_without_mime.webp',
    mimeType: 'application/octet-stream',
    fileSize: 8000,
  });
}

function createDocumentMessage({
  chatId = '-100123',
  messageId = 56,
  fileId = 'document-file',
  fileName = 'photo.webp',
  mimeType = 'application/octet-stream',
  fileSize = 8000,
} = {}) {
  return {
    message_id: messageId,
    chat: { id: chatId, type: 'supergroup' },
    document: {
      file_id: fileId,
      file_name: fileName,
      mime_type: mimeType,
      file_size: fileSize,
    },
  };
}

function createHeicDocumentMessage(chatId = '-100123') {
  return {
    message_id: 57,
    chat: { id: chatId, type: 'supergroup' },
    document: {
      file_id: 'heic-file',
      file_name: 'iphone_photo.HEIC',
      mime_type: 'application/octet-stream',
      file_size: 6439456,
    },
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
      assert.match(payload.file_id, /^(large-file|document-file|heic-file|format-file-|magic-file)/);
      if (payload.file_id === 'document-file') return { file_path: 'documents/source.webp' };
      if (payload.file_id === 'heic-file') return { file_path: 'documents/source.heic' };
      if (String(payload.file_id).startsWith('format-file-')) {
        return { file_path: `documents/source.${String(payload.file_id).replace('format-file-', '')}` };
      }
      if (payload.file_id === 'magic-file') return { file_path: 'documents/source' };
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

test('telegram dev photo cleaner accepts image documents by filename when MIME is generic', async () => {
  const { calls, deps, cleanup } = createDeps();
  try {
    const handled = await handleStuderriaTelegramDevPhotoCleanerMessage(createImageDocumentMessage(), deps);
    assert.equal(handled, true);
    assert.deepEqual(
      calls.map((entry) => entry[0]),
      ['callBotApi', 'fetch', 'clean', 'sendDocument', 'deleteMessage', 'log']
    );
    assert.deepEqual(calls[2], ['clean', true, 'webp']);
    assert.deepEqual(calls[4], ['deleteMessage', '-100123', 56, 'dev photo cleaner original']);
  } finally {
    cleanup();
  }
});

test('telegram dev photo cleaner converts HEIC documents to cleaned JPEG', async () => {
  const { calls, deps, cleanup } = createDeps();
  try {
    const handled = await handleStuderriaTelegramDevPhotoCleanerMessage(createHeicDocumentMessage(), deps);
    assert.equal(handled, true);
    assert.deepEqual(
      calls.map((entry) => entry[0]),
      ['callBotApi', 'fetch', 'clean', 'sendDocument', 'deleteMessage', 'log']
    );
    assert.deepEqual(calls[2], ['clean', true, 'jpg']);
    assert.deepEqual(calls[4], ['deleteMessage', '-100123', 57, 'dev photo cleaner original']);
  } finally {
    cleanup();
  }
});

test('telegram dev photo cleaner downloads generic documents without filenames for path detection', async () => {
  const { calls, deps, cleanup } = createDeps();
  try {
    const handled = await handleStuderriaTelegramDevPhotoCleanerMessage(createDocumentMessage({
      messageId: 58,
      fileId: 'heic-file',
      fileName: '',
      mimeType: 'application/octet-stream',
      fileSize: 6439456,
    }), deps);
    assert.equal(handled, true);
    assert.deepEqual(
      calls.map((entry) => entry[0]),
      ['callBotApi', 'fetch', 'clean', 'sendDocument', 'deleteMessage', 'log']
    );
    assert.deepEqual(calls[2], ['clean', true, 'jpg']);
  } finally {
    cleanup();
  }
});

test('telegram dev photo cleaner logs unsupported documents in allowed dev chat', async () => {
  const { calls, deps, cleanup } = createDeps();
  try {
    const handled = await handleStuderriaTelegramDevPhotoCleanerMessage(createDocumentMessage({
      messageId: 59,
      fileId: 'pdf-file',
      fileName: 'notes.pdf',
      mimeType: 'application/pdf',
      fileSize: 12000,
    }), deps);
    assert.equal(handled, false);
    assert.deepEqual(calls.map((entry) => entry[0]), ['warn']);
    assert.equal(calls[0][2].reason, 'unsupported_media');
    assert.equal(calls[0][2].content_type, 'application/pdf');
    assert.equal(calls[0][2].file_ext, 'pdf');
  } finally {
    cleanup();
  }
});

test('telegram dev photo cleaner accepts popular raster document formats', async () => {
  const cases = [
    ['avif', 'image/avif', 'avif'],
    ['tif', 'image/tiff', 'tiff'],
    ['tiff', 'application/octet-stream', 'tiff'],
    ['gif', 'image/gif', 'gif'],
    ['bmp', 'application/octet-stream', 'png'],
    ['jfif', 'application/octet-stream', 'jpg'],
  ];

  for (const [extension, mimeType, outputExtension] of cases) {
    const { calls, deps, cleanup } = createDeps();
    try {
      const handled = await handleStuderriaTelegramDevPhotoCleanerMessage(createDocumentMessage({
        messageId: 70,
        fileId: `format-file-${extension}`,
        fileName: `sample.${extension}`,
        mimeType,
      }), deps);
      assert.equal(handled, true, extension);
      assert.deepEqual(calls[2], ['clean', true, outputExtension]);
      assert.ok(calls.some((entry) => entry[0] === 'deleteMessage'), extension);
    } finally {
      cleanup();
    }
  }
});

test('telegram dev photo cleaner can infer common formats from downloaded bytes', () => {
  const samples = [
    [Buffer.from([0xff, 0xd8, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 'jpg'],
    [Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x00]), 'png'],
    [Buffer.from('RIFF0000WEBPVP8 ', 'ascii'), 'webp'],
    [Buffer.from('GIF89a000000', 'ascii'), 'gif'],
    [Buffer.from([0x49, 0x49, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 'tiff'],
    [Buffer.from('BM0000000000', 'ascii'), 'png'],
    [Buffer.from('\x00\x00\x00\x18ftypavif0000', 'binary'), 'avif'],
    [Buffer.from('\x00\x00\x00\x18ftypheic0000', 'binary'), 'jpg'],
  ];

  for (const [buffer, outputExtension] of samples) {
    assert.equal(getImageTypeFromBuffer(buffer).extension, outputExtension);
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
