/**
 * Lightweight magic-bytes validation for uploaded files.
 * Checks actual file content rather than trusting the client-supplied MIME type.
 */

const SIGNATURES = [
  { mime: 'image/png', ext: 'png', magic: Buffer.from([0x89, 0x50, 0x4E, 0x47]) },
  { mime: 'image/jpeg', ext: 'jpg', magic: Buffer.from([0xFF, 0xD8, 0xFF]) },
  { mime: 'image/gif', ext: 'gif', magic: Buffer.from([0x47, 0x49, 0x46, 0x38]) },
  { mime: 'application/pdf', ext: 'pdf', magic: Buffer.from([0x25, 0x50, 0x44, 0x46]) },
  // DOCX, XLSX, PPTX are ZIP archives (PK header)
  { mime: 'application/zip', ext: 'zip', magic: Buffer.from([0x50, 0x4B, 0x03, 0x04]) },
  // DOC, XLS, PPT legacy OLE compound documents
  { mime: 'application/msword', ext: 'doc', magic: Buffer.from([0xD0, 0xCF, 0x11, 0xE0]) },
];

// Map of allowed MIME types to their expected magic byte families
const MIME_TO_MAGIC_FAMILY = new Map([
  ['image/png', 'image/png'],
  ['image/jpeg', 'image/jpeg'],
  ['image/gif', 'image/gif'],
  ['application/pdf', 'application/pdf'],
  ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
  ['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'],
  ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
  ['application/msword', 'application/msword'],
  ['application/vnd.ms-powerpoint', 'application/msword'],
  ['application/vnd.ms-excel', 'application/msword'],
]);

/**
 * Detect the file type from a Buffer by checking magic bytes.
 * @param {Buffer} buffer - File content (at least first 8 bytes)
 * @returns {{ mime: string, ext: string } | null}
 */
function detectFileType(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 3) {
    return null;
  }
  for (const sig of SIGNATURES) {
    if (buffer.length >= sig.magic.length && buffer.subarray(0, sig.magic.length).equals(sig.magic)) {
      return { mime: sig.mime, ext: sig.ext };
    }
  }
  return null;
}

/**
 * Check if file content matches its claimed MIME type.
 * For text/plain files, we allow anything that doesn't match a binary signature.
 *
 * @param {Buffer} buffer - File content
 * @param {string} claimedMime - The MIME type provided by the client
 * @returns {{ valid: boolean, detectedMime: string | null, reason?: string }}
 */
function validateFileContent(buffer, claimedMime) {
  const normalizedMime = String(claimedMime || '').trim().toLowerCase();

  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return { valid: false, detectedMime: null, reason: 'empty_file' };
  }

  // text/plain: allow if content has no known binary signature
  if (normalizedMime === 'text/plain') {
    const detected = detectFileType(buffer);
    if (detected) {
      return { valid: false, detectedMime: detected.mime, reason: 'binary_as_text' };
    }
    return { valid: true, detectedMime: null };
  }

  // CSV types: same as text — no binary signature expected
  if (normalizedMime === 'text/csv' || normalizedMime === 'application/csv') {
    const detected = detectFileType(buffer);
    if (detected) {
      return { valid: false, detectedMime: detected.mime, reason: 'binary_as_csv' };
    }
    return { valid: true, detectedMime: null };
  }

  // Binary types: verify magic bytes match expected family
  const expectedFamily = MIME_TO_MAGIC_FAMILY.get(normalizedMime);
  if (!expectedFamily) {
    // Unknown MIME type — allow but warn
    return { valid: true, detectedMime: null, reason: 'unknown_mime' };
  }

  const detected = detectFileType(buffer);
  if (!detected) {
    return { valid: false, detectedMime: null, reason: 'no_magic_bytes' };
  }

  if (detected.mime !== expectedFamily) {
    return { valid: false, detectedMime: detected.mime, reason: 'mime_mismatch' };
  }

  return { valid: true, detectedMime: detected.mime };
}

module.exports = {
  detectFileType,
  validateFileContent,
  SIGNATURES,
};
