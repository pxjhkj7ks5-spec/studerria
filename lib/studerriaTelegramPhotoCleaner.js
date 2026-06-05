const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULT_MAX_IMAGE_BYTES = 20 * 1024 * 1024;
const TRUE_ENV_VALUES = new Set(['1', 'true', 'yes', 'on']);
const SUPPORTED_IMAGE_TYPES = new Map([
  ['image/jpeg', { extension: 'jpg', format: 'jpeg', contentType: 'image/jpeg', sourceFormat: 'jpeg' }],
  ['image/jpg', { extension: 'jpg', format: 'jpeg', contentType: 'image/jpeg', sourceFormat: 'jpeg' }],
  ['image/png', { extension: 'png', format: 'png', contentType: 'image/png', sourceFormat: 'png' }],
  ['image/webp', { extension: 'webp', format: 'webp', contentType: 'image/webp', sourceFormat: 'webp', animated: true }],
  ['image/avif', { extension: 'avif', format: 'avif', contentType: 'image/avif', sourceFormat: 'avif' }],
  ['image/tiff', { extension: 'tiff', format: 'tiff', contentType: 'image/tiff', sourceFormat: 'tiff' }],
  ['image/gif', { extension: 'gif', format: 'gif', contentType: 'image/gif', sourceFormat: 'gif', animated: true }],
  ['image/bmp', { extension: 'png', format: 'png', contentType: 'image/png', sourceFormat: 'bmp' }],
  ['image/x-bmp', { extension: 'png', format: 'png', contentType: 'image/png', sourceFormat: 'bmp' }],
  ['image/x-ms-bmp', { extension: 'png', format: 'png', contentType: 'image/png', sourceFormat: 'bmp' }],
  ['image/heic', { extension: 'jpg', format: 'jpeg', contentType: 'image/jpeg', sourceFormat: 'heic' }],
  ['image/heif', { extension: 'jpg', format: 'jpeg', contentType: 'image/jpeg', sourceFormat: 'heic' }],
  ['image/heic-sequence', { extension: 'jpg', format: 'jpeg', contentType: 'image/jpeg', sourceFormat: 'heic' }],
  ['image/heif-sequence', { extension: 'jpg', format: 'jpeg', contentType: 'image/jpeg', sourceFormat: 'heic' }],
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
  if (normalized === 'image/x-tiff') return 'image/tiff';
  if (normalized === 'image/heif') return 'image/heif';
  if (normalized === 'image/heic') return 'image/heic';
  return normalized;
}

function isGenericDocumentContentType(contentType = '') {
  return !contentType
    || contentType === 'application/octet-stream'
    || contentType === 'binary/octet-stream'
    || contentType === 'application/x-download';
}

function getImageTypeFromFilePath(filePath = '') {
  const extension = path.extname(String(filePath || '')).replace('.', '').toLowerCase();
  return getImageTypeFromExtension(extension);
}

function getImageTypeFromExtension(extension = '') {
  const normalized = String(extension || '').replace(/^\./, '').toLowerCase();
  if (normalized === 'jpg' || normalized === 'jpeg' || normalized === 'jpe' || normalized === 'jfif') return SUPPORTED_IMAGE_TYPES.get('image/jpeg');
  if (normalized === 'png') return SUPPORTED_IMAGE_TYPES.get('image/png');
  if (normalized === 'webp') return SUPPORTED_IMAGE_TYPES.get('image/webp');
  if (normalized === 'avif') return SUPPORTED_IMAGE_TYPES.get('image/avif');
  if (normalized === 'tif' || normalized === 'tiff') return SUPPORTED_IMAGE_TYPES.get('image/tiff');
  if (normalized === 'gif') return SUPPORTED_IMAGE_TYPES.get('image/gif');
  if (normalized === 'bmp' || normalized === 'dib') return SUPPORTED_IMAGE_TYPES.get('image/bmp');
  if (normalized === 'heic') return SUPPORTED_IMAGE_TYPES.get('image/heic');
  if (normalized === 'heif') return SUPPORTED_IMAGE_TYPES.get('image/heif');
  return null;
}

function getImageTypeFromBuffer(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return SUPPORTED_IMAGE_TYPES.get('image/jpeg');
  if (buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return SUPPORTED_IMAGE_TYPES.get('image/png');
  if (buffer.subarray(0, 4).toString('ascii') === 'RIFF' && buffer.subarray(8, 12).toString('ascii') === 'WEBP') return SUPPORTED_IMAGE_TYPES.get('image/webp');
  const gifHeader = buffer.subarray(0, 6).toString('ascii');
  if (gifHeader === 'GIF87a' || gifHeader === 'GIF89a') return SUPPORTED_IMAGE_TYPES.get('image/gif');
  if (
    buffer.subarray(0, 4).equals(Buffer.from([0x49, 0x49, 0x2a, 0x00]))
    || buffer.subarray(0, 4).equals(Buffer.from([0x4d, 0x4d, 0x00, 0x2a]))
  ) {
    return SUPPORTED_IMAGE_TYPES.get('image/tiff');
  }
  if (buffer.subarray(0, 2).toString('ascii') === 'BM') return SUPPORTED_IMAGE_TYPES.get('image/bmp');
  if (buffer.subarray(4, 8).toString('ascii') === 'ftyp') {
    const brands = buffer.subarray(8, Math.min(buffer.length, 64)).toString('ascii');
    if (/(avif|avis)/.test(brands)) return SUPPORTED_IMAGE_TYPES.get('image/avif');
    if (/(heic|heix|hevc|hevx|heim|heis|hevm|hevs|heif|mif1|msf1)/.test(brands)) return SUPPORTED_IMAGE_TYPES.get('image/heic');
  }
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
  const fileExtension = path.extname(document.file_name || '').replace('.', '').toLowerCase();
  const filenameImageType = getImageTypeFromExtension(fileExtension);
  if (
    contentType
    && !contentType.startsWith('image/')
    && !filenameImageType
    && !isGenericDocumentContentType(contentType)
  ) {
    return null;
  }
  if (!contentType && !filenameImageType && !document.file_id) return null;
  const imageType = SUPPORTED_IMAGE_TYPES.get(contentType) || filenameImageType || null;
  return {
    kind: 'document',
    sendAs: 'document',
    fileId: document.file_id,
    fileSize: Number(document.file_size || 0) || null,
    contentType: imageType && imageType.contentType ? imageType.contentType : contentType,
    sourceContentType: contentType || null,
    sourceFileExtension: fileExtension || null,
    imageType,
  };
}

function getStuderriaTelegramCleanerCandidateContext(message = {}) {
  const photo = selectLargestTelegramPhotoSize(Array.isArray(message.photo) ? message.photo : []);
  if (photo) {
    return {
      mediaKind: 'photo',
      fileSize: Number(photo.file_size || 0) || null,
      contentType: 'image/jpeg',
      fileExtension: 'jpg',
    };
  }
  const document = message && message.document ? message.document : null;
  if (!document || !document.file_id) return null;
  return {
    mediaKind: 'document',
    fileSize: Number(document.file_size || 0) || null,
    contentType: normalizeImageMimeType(document.mime_type) || null,
    fileExtension: path.extname(document.file_name || '').replace('.', '').toLowerCase() || null,
  };
}

function logStuderriaDevPhotoCleaner(logger, status, details = {}) {
  const payload = {
    reason: details.reason || null,
    chat_id: details.chatId || null,
    message_id: details.messageId || null,
    media_kind: details.mediaKind || null,
    file_size: details.fileSize || null,
    content_type: details.contentType || null,
    file_ext: details.fileExtension || null,
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
  if (imageType.sourceFormat === 'heic') {
    return cleanHeicMetadataToJpeg(buffer);
  }
  const inputOptions = imageType.animated ? { animated: true } : {};
  const pipeline = sharp(buffer, inputOptions).rotate();
  if (imageType.format === 'jpeg') return pipeline.jpeg({ quality: 92 }).toBuffer();
  if (imageType.format === 'png') return pipeline.png({ compressionLevel: 9 }).toBuffer();
  if (imageType.format === 'webp') return pipeline.webp({ quality: 92 }).toBuffer();
  if (imageType.format === 'avif') return pipeline.avif({ quality: 80 }).toBuffer();
  if (imageType.format === 'tiff') return pipeline.tiff({ quality: 90, compression: 'jpeg' }).toBuffer();
  if (imageType.format === 'gif') return pipeline.gif().toBuffer();
  throw new Error('unsupported_image_type');
}

async function cleanHeicMetadataToJpeg(buffer) {
  const convert = require('heic-convert');
  const output = await convert({
    buffer,
    format: 'JPEG',
    quality: 0.92,
  });
  return Buffer.from(output);
}

async function handleStuderriaTelegramDevPhotoCleanerMessage(message = {}, deps = {}) {
  const media = getStuderriaTelegramCleanerMedia(message);
  const candidateContext = media ? null : getStuderriaTelegramCleanerCandidateContext(message);
  if (!media && !candidateContext) return false;

  const env = deps.env || process.env;
  const logger = deps.logger || console;
  const chatId = normalizeTelegramChatId(message && message.chat && message.chat.id);
  const messageId = message && message.message_id ? message.message_id : null;
  const logContext = {
    chatId,
    messageId,
    mediaKind: media ? media.kind : candidateContext.mediaKind,
    fileSize: media ? media.fileSize : candidateContext.fileSize,
    contentType: media ? (media.sourceContentType || media.contentType || null) : candidateContext.contentType,
    fileExtension: media ? (media.sourceFileExtension || null) : candidateContext.fileExtension,
  };

  if (!isStuderriaDevPhotoCleanerEnabled(env)) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', { ...logContext, reason: 'disabled' });
    return false;
  }
  if (!chatId || !getStuderriaDevPhotoCleanerChatIds(env).has(chatId)) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', { ...logContext, reason: 'not_allowed_chat' });
    return false;
  }
  if (!media) {
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
  const detectedImageType = pathImageType || media.imageType || getImageTypeFromBuffer(download.buffer);
  if (!detectedImageType) {
    logStuderriaDevPhotoCleaner(logger, 'skipped', { ...logContext, reason: 'unsupported_media' });
    return true;
  }
  const cleanMedia = { ...media, imageType: detectedImageType, contentType: detectedImageType.contentType };
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
  getImageTypeFromBuffer,
  getStuderriaDevPhotoCleanerChatIds,
  getStuderriaTelegramCleanerMedia,
  handleStuderriaTelegramDevPhotoCleanerMessage,
  isStuderriaDevPhotoCleanerEnabled,
  selectLargestTelegramPhotoSize,
};
