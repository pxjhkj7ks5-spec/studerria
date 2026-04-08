const test = require('node:test');
const assert = require('node:assert/strict');

const { detectFileType, validateFileContent } = require('../lib/fileValidation');

test('detectFileType recognizes PNG magic bytes', () => {
  const pngHeader = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const result = detectFileType(pngHeader);
  assert.equal(result.mime, 'image/png');
  assert.equal(result.ext, 'png');
});

test('detectFileType recognizes JPEG magic bytes', () => {
  const jpegHeader = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]);
  const result = detectFileType(jpegHeader);
  assert.equal(result.mime, 'image/jpeg');
  assert.equal(result.ext, 'jpg');
});

test('detectFileType recognizes PDF magic bytes', () => {
  const pdfHeader = Buffer.from('%PDF-1.7');
  const result = detectFileType(pdfHeader);
  assert.equal(result.mime, 'application/pdf');
  assert.equal(result.ext, 'pdf');
});

test('detectFileType recognizes ZIP/DOCX magic bytes', () => {
  const zipHeader = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00]);
  const result = detectFileType(zipHeader);
  assert.equal(result.mime, 'application/zip');
});

test('detectFileType recognizes OLE/DOC magic bytes', () => {
  const oleHeader = Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
  const result = detectFileType(oleHeader);
  assert.equal(result.mime, 'application/msword');
});

test('detectFileType returns null for unknown content', () => {
  const text = Buffer.from('Hello world');
  assert.equal(detectFileType(text), null);
});

test('detectFileType returns null for empty buffer', () => {
  assert.equal(detectFileType(Buffer.alloc(0)), null);
});

test('validateFileContent accepts PNG with correct MIME', () => {
  const png = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const result = validateFileContent(png, 'image/png');
  assert.equal(result.valid, true);
});

test('validateFileContent rejects JPEG disguised as PNG', () => {
  const jpeg = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]);
  const result = validateFileContent(jpeg, 'image/png');
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'mime_mismatch');
  assert.equal(result.detectedMime, 'image/jpeg');
});

test('validateFileContent accepts DOCX (ZIP magic) with Office MIME', () => {
  const zip = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00]);
  const result = validateFileContent(zip, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
  assert.equal(result.valid, true);
});

test('validateFileContent accepts text/plain without binary signature', () => {
  const text = Buffer.from('Just some plain text content');
  const result = validateFileContent(text, 'text/plain');
  assert.equal(result.valid, true);
});

test('validateFileContent rejects binary file disguised as text', () => {
  const png = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const result = validateFileContent(png, 'text/plain');
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'binary_as_text');
});

test('validateFileContent rejects PDF with no magic bytes', () => {
  const text = Buffer.from('This is not a PDF');
  const result = validateFileContent(text, 'application/pdf');
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'no_magic_bytes');
});

test('validateFileContent accepts CSV without binary signature', () => {
  const csv = Buffer.from('name,age\nAlice,30\nBob,25');
  const result = validateFileContent(csv, 'text/csv');
  assert.equal(result.valid, true);
});

test('validateFileContent rejects binary disguised as CSV', () => {
  const exe = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A]);
  const result = validateFileContent(exe, 'text/csv');
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'binary_as_csv');
});

test('validateFileContent rejects empty file', () => {
  const result = validateFileContent(Buffer.alloc(0), 'image/png');
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'empty_file');
});
