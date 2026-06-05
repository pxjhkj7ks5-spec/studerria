const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULT_MAX_IMAGE_BYTES = 20 * 1024 * 1024;
const TRUE_ENV_VALUES = new Set(['1', 'true', 'yes', 'on']);
const SUPPORTED_IMAGE_TYPES = new Map([
  ['image/jpeg', { extension: 'jpg', format: 'jpeg', contentType: 'image/jpeg' }],
  ['image/jpg', { extension: 'jpg', format: 'jpeg', contentType: 'image/jpeg' }],
  ['image/png', { extension: 'png', format: 'png', contentType: 'image/png' }],
  ['image/webp', { extension: 'webp', format: 'webp', contentType: 'image/webp' }],
]);

function normalizeTelegramChatId(value) {
  return String(value || '').trim();
}

function isStuderriaDevPhotoCleanerEnabled(env = process.env) {
  return TRUE_ENV_VALUES.has(String(env.STUDERRIA_TG_DEV_PHOTO_CLEANER_ENABLED || '').trim().toLowerCase());
}

function getStuderriaDevPhotoCleanerChatIds(env = process.env) {
  return new Set(
    String(env.STUDERRIA_TG_DEV_PHOTO_CLEANER_CHAT_IDS || '')
      .split(/[\s,;]+/)
      .map((value) => normalizeTelegramChatId(value))
      .filter(Boolean)
  );
}

function getStuderriaDevPhotoCleanerMaxBytes(env = process.env) {
  const parsed = Number(env.STUDERRIA_TG_DEV_PHOTO_CLEANER_MAX_BYTES || 0);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : DEFAULT_MAX_IMAGE_BYTES;
}

function scoreTelegramPhotoSize(photo = {}) {
  const fileSize = Number(photo.file_size || 0);
  if (Number.isFinite(fileSize) && fileSize > 0) return fileSize;
  const width = Number(photo.width || 0);
  const height = Number(photo.height || 0);
  return Math.max(0, width) * Math.max(0, height);
}

function selectLargestTelegramPhotoSize(photos = []) {
  return photos
    .filter((photo) => photo && photo.file_id)
    .slice()
    .sort((a, b) => scoreTelegramPhotoSize(b) - scoreTelegramPhotoSize(a))[0] || null;
}

function normalizeImageMimeType(value = '') {
  const normalized = String(value || '').split(';')[0].trim().toLowerCase();
  if (normalized === 'image/jpg') return 'image/jpeg';
  return normalized;
}

function getImageTypeFromFilePath(filePath = '') {
  const extension = path.extname(String(filePath || '')).replace('.', '').toLowerCase();
  if (extension === 'jpg' || extension === 'jpeg') return SUPPORTED_IMAGE_TYPES.get('image/jpeg');
  if (extension === 'png') return SUPPORTED_IMAGE_TYPES.get('image/png');
  if (extension === 'webp') return SUPPORTED_IMAGE_TYPES.get('image/webp');
  return null;
}

function getStuderriaTelegramCleanerMedia(message = {}) {
  const photo = selectLargestTelegramPhotoSize(Array.isArray(message.photo) ? message.photo : []);
  if (photo) {
    return {
      kind: 'photo',
      sendAs: 'photo',
      fileId: photo.file_id,
      fileSize: Number(photo.file_size || 0) || null,
      contentType: 'image/jpeg',
      imageType: SUPPORTED_IMAGE_TYPES.get('image/jpeg'),
    };
  }

  const document = message && message.document ? message.document : null;
  if (!document || !document.file_id) return null;
  const contentType = normalizeImageMimeType(document.mime_type);
  if (!contentType.startsWith('image/')) return null;
  const imageType = SUPPORTED_IMAGE_TYPES.get(contentType) || null;
  return {
    kind: 'document',
    sendAs: 'document',
    fileId: document.file_id,
    fileSize: Number(document.file_size || 0) || null,
    contentType,
    imageType,
  };
}

function logStuderriaDevPhotoCleaner(logger, status, details = {}) {
  const payload = {
    reason: details.reason || null,
    chat_id: details.chatId || null,
    message_id: details.messageId || null,
    media_kind: details.mediaKind || null,
    file_size: details.fileSize || null,
  };
  if (status === 'success') {
    const log = logger && typeof logger.log === 'function' ? logger.log.bind(logger) : console.log;
    log('Studerria Telegram dev photo cleaner success', payload);
    return;
  }
  const warn = logger && typeof logger.warn === 'function' ? logger.warn.bind(logger) : console.warn;
  warn('Studerria Telegram dev photo cleaner skipped', payload);
}

function buildTelegramFileUrl(token, filePath) {
  const encodedPath = String(filePath || '')
    .split('/')
    .map((part) => encodeURIComponent(part))
    .join('/');
  return `https://api.telegram.org/file/bot${token}/${encodedPath}`;
}

async function downloadStuderriaTelegramFile(media, deps = {}) {
  const callBotApi = deps.callBotApi;
  const getBotToken = deps.getBotToken;
  const fetchImpl = deps.fetch || globalThis.fetch;
  if (typeof callBotApi !== 'function') throw new Error('missing_call_bot_api');
  if (typeof getBotToken !== 'function') throw new Error('missing_bot_token_provider');
  if (typeof fetchImpl !== 'function') throw new Error('missing_fetch');

  const file = await callBotApi('getFile', { file_id: media.fileId });
  const filePath = file && file.file_path ? String(file.file_path) : '';
  if (!filePath) throw new Error('missing_file_path');

  const token = String(getBotToken() || '').trim();
  if (!token) throw new Error('missing_bot_token');
  const response = await fetchImpl(buildTelegramFileUrl(token, filePath));
  if (!response || !response.ok) throw new Error('telegram_file_download_failed');
  const arrayBuffer = await response.arrayBuffer();
  return {
    buffer: Buffer.from(arrayBuffer),
    filePath,
  };
}

async function cleanImageMetadataWithSharp(buffer, media = {}) {
  const sharp = require('sharp');
  const imageType = media.imageType || SUPPORTED_IMAGE_TYPES.get(normalizeImageMimeType(media.contentType));
  if (!imageType) throw new Error('unsupported_image_type');
  const pipeline = sharp(buffer).rotate();
  if (imageType.format === 'jpeg') return pipeline.jpeg({ quality: 92 }).toBuffer();
  if (imageType.format === 'png') return pipeline.png({ compressionLevel: 9 }).toBuffer();
  if (imageType.format === 'webp') return pipeline.webp({ quality: 92 }).toBuffer();
  throw new Error('unsupported_image_type');
}

async function handleStuderriaTelegramDevPhotoCleanerMessage(message = {}, deps = {}) {
  const media = getStuderriaTelegramCleanerMedia(message);
  if (!media) return false;

  const env = deps.env || process.env;
  const logger = deps.logger || console;
  const chatId = normalizeTelegramChatId(message && message.chat && message.chat.id);
  const messageId = message && message.message_id ? message.message_id : null;
  const logContext = {
    chatId,
    messageId,
    mediaKind: media.kind,
    fileSize: media.fileSize,
  };

  if (!isStuderriaDevPhotoCleanerEnabled(env)) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', { ...logContext, reason: 'disabled' });
    return false;
  }
  if (!chatId || !getStuderriaDevPhotoCleanerChatIds(env).has(chatId)) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', { ...logContext, reason: 'not_allowed_chat' });
    return false;
  }
  if (!media.imageType) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', { ...logContext, reason: 'unsupported_media' });
    return false;
  }

  const maxBytes = getStuderriaDevPhotoCleanerMaxBytes(env);
  if (media.fileSize && media.fileSize > maxBytes) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', { ...logContext, reason: 'unsupported_media' });
    return false;
  }

  let download;
  try {
    download = await downloadStuderriaTelegramFile(media, deps);
  } catch (err) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', { ...logContext, reason: 'download_failed' });
    return true;
  }
  if (!download.buffer || download.buffer.length > maxBytes) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', {
      ...logContext,
      reason: 'unsupported_media',
      fileSize: download.buffer ? download.buffer.length : media.fileSize,
    });
    return true;
  }

  const pathImageType = getImageTypeFromFilePath(download.filePath);
  const cleanMedia = pathImageType
    ? { ...media, imageType: pathImageType, contentType: pathImageType.contentType }
    : media;
  let cleanedBuffer;
  try {
    const cleaner = deps.cleanImageMetadata || cleanImageMetadataWithSharp;
    cleanedBuffer = await cleaner(download.buffer, cleanMedia);
  } catch (err) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', { ...logContext, reason: 'clean_failed' });
    return true;
  }
  if (!Buffer.isBuffer(cleanedBuffer) || cleanedBuffer.length <= 0 || cleanedBuffer.length > maxBytes) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', {
      ...logContext,
      reason: 'clean_failed',
      fileSize: cleanedBuffer && cleanedBuffer.length ? cleanedBuffer.length : media.fileSize,
    });
    return true;
  }

  const tmpRoot = deps.tmpRoot || os.tmpdir();
  let tmpDir = null;
  try {
    tmpDir = await fs.promises.mkdtemp(path.join(tmpRoot, 'studerria-tg-clean-'));
    const outputPath = path.join(tmpDir, `cleaned.${cleanMedia.imageType.extension}`);
    await fs.promises.writeFile(outputPath, cleanedBuffer);
    const sendOptions = {
      contentType: cleanMedia.contentType,
      filename: `cleaned.${cleanMedia.imageType.extension}`,
      caption: message.caption || '',
      sourceMessage: message,
    };
    if (typeof deps.getMessageThreadId === 'function') {
      const threadId = deps.getMessageThreadId(message);
      if (threadId) sendOptions.messageThreadId = threadId;
    }
    const sender = media.sendAs === 'document' ? deps.sendDocument : deps.sendPhoto;
    if (typeof sender !== 'function') throw new Error('missing_sender');
    const sendResult = await sender(chatId, outputPath, sendOptions);
    if (!sendResult) throw new Error('send_returned_empty');
  } catch (err) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', { ...logContext, reason: 'send_failed' });
    return true;
  } finally {
    if (tmpDir) {
      await fs.promises.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  try {
    if (typeof deps.deleteMessage !== 'function') throw new Error('missing_delete_message');
    const deleteResult = await deps.deleteMessage(chatId, messageId, 'dev photo cleaner original');
    if (!deleteResult) throw new Error('delete_returned_empty');
  } catch (err) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', { ...logContext, reason: 'delete_failed' });
    return true;
  }

  logStuderriaDevPhotoCleaner(logger, 'success', logContext);
  return true;
}

module.exports = {
  DEFAULT_MAX_IMAGE_BYTES,
  cleanImageMetadataWithSharp,
  getStuderriaDevPhotoCleanerChatIds,
  getStuderriaTelegramCleanerMedia,
  handleStuderriaTelegramDevPhotoCleanerMessage,
  isStuderriaDevPhotoCleanerEnabled,
  selectLargestTelegramPhotoSize,
};
