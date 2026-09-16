'use strict';

const yauzl = require('yauzl');
const { cleanInstagramUsername } = require('../collectors/instagram');
const { normalizeEntityInput, normalizeRelationshipInput } = require('../security/validation');

const EXPORT_PATH = /(?:^|\/)followers_and_following\/(followers(?:_\d+)?|following)\.json$/i;

function exportRows(value, kind) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== 'object') return [];
  if (kind === 'following' && Array.isArray(value.relationships_following)) return value.relationships_following;
  if (kind === 'followers' && Array.isArray(value.relationships_followers)) return value.relationships_followers;
  return [];
}

function usernameFromExportRow(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return null;
  const detail = Array.isArray(row.string_list_data) ? row.string_list_data.find((item) => item && typeof item === 'object') : null;
  let candidate = detail?.value || row.title || '';
  if (!candidate && typeof detail?.href === 'string') {
    try { candidate = new URL(detail.href).pathname.split('/').filter(Boolean)[0] || ''; } catch (_error) { return null; }
  }
  try {
    return {
      username: cleanInstagramUsername(candidate),
      timestamp: Number.isFinite(Number(detail?.timestamp)) ? Number(detail.timestamp) : null,
    };
  } catch (_error) {
    return null;
  }
}

function parseInstagramExportDocuments(documents, { ownerUsername, maxRecords = 5000 } = {}) {
  const owner = cleanInstagramUsername(ownerUsername);
  const ownerKey = `instagram:${owner}`;
  const entities = new Map();
  const relationships = new Map();
  entities.set(ownerKey, normalizeEntityInput({
    id: ownerKey, type: 'SOCIAL_ACCOUNT', platform: 'instagram', username: owner,
    name: `@${owner}`, url: `https://www.instagram.com/${owner}/`,
    metadata: { source: 'instagram-data-export', export_owner: true },
  }));

  for (const document of documents) {
    const kind = document.kind === 'following' ? 'following' : 'followers';
    for (const row of exportRows(document.value, kind)) {
      const parsed = usernameFromExportRow(row);
      if (!parsed || parsed.username === owner) continue;
      const accountKey = `instagram:${parsed.username}`;
      if (!entities.has(accountKey)) {
        entities.set(accountKey, normalizeEntityInput({
          id: accountKey, type: 'SOCIAL_ACCOUNT', platform: 'instagram', username: parsed.username,
          name: `@${parsed.username}`, url: `https://www.instagram.com/${parsed.username}/`,
          metadata: { source: 'instagram-data-export' },
        }));
      }
      const source = kind === 'followers' ? accountKey : ownerKey;
      const target = kind === 'followers' ? ownerKey : accountKey;
      const relationshipKey = `${source}|${target}|FOLLOWS`;
      relationships.set(relationshipKey, normalizeRelationshipInput({
        source, target, type: 'FOLLOWS', weight: 1, confidence: 1,
        source_url: `https://www.instagram.com/${owner}/${kind}/`,
        metadata: {
          source: 'instagram-data-export', source_export_file: document.name,
          direct_platform_export: true, export_record_timestamp: parsed.timestamp,
        },
      }));
      if (entities.size + relationships.size > maxRecords) throw new Error('too_many_records');
    }
  }
  if (relationships.size === 0) throw new Error('instagram_export_no_connections');
  return { entities: Array.from(entities.values()), relationships: Array.from(relationships.values()) };
}

function openZip(buffer) {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true, decodeStrings: true, validateEntrySizes: true }, (error, zip) => {
      if (error) reject(new Error('invalid_instagram_export_zip'));
      else resolve(zip);
    });
  });
}

function readEntry(zip, entry, maxBytes) {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (error, stream) => {
      if (error) return reject(new Error('invalid_instagram_export_zip'));
      const chunks = [];
      let total = 0;
      stream.on('data', (chunk) => {
        total += chunk.length;
        if (total > maxBytes) stream.destroy(new Error('instagram_export_too_large'));
        else chunks.push(chunk);
      });
      stream.on('error', (streamError) => reject(streamError.message === 'instagram_export_too_large' ? streamError : new Error('invalid_instagram_export_zip')));
      stream.on('end', () => resolve(Buffer.concat(chunks)));
      return undefined;
    });
  });
}

async function parseInstagramExportZip(buffer, { ownerUsername, maxRecords = 5000, maxUncompressedBytes = 10 * 1024 * 1024 } = {}) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4 || buffer.readUInt32LE(0) !== 0x04034b50) throw new Error('invalid_instagram_export_zip');
  const zip = await openZip(buffer);
  const documents = [];
  let entriesSeen = 0;
  let uncompressedTotal = 0;

  await new Promise((resolve, reject) => {
    zip.on('entry', async (entry) => {
      try {
        entriesSeen += 1;
        if (entriesSeen > 500) throw new Error('instagram_export_too_many_files');
        const normalizedName = String(entry.fileName || '').replace(/\\/g, '/');
        const match = normalizedName.match(EXPORT_PATH);
        if (!match) return zip.readEntry();
        if ((entry.generalPurposeBitFlag & 0x1) !== 0) throw new Error('encrypted_import_not_supported');
        uncompressedTotal += Number(entry.uncompressedSize || 0);
        if (uncompressedTotal > maxUncompressedBytes) throw new Error('instagram_export_too_large');
        const data = await readEntry(zip, entry, maxUncompressedBytes);
        let value;
        try { value = JSON.parse(data.toString('utf8')); } catch (_error) { throw new Error('invalid_instagram_export_json'); }
        documents.push({ name: normalizedName.slice(0, 500), kind: match[1].toLowerCase().startsWith('following') ? 'following' : 'followers', value });
        return zip.readEntry();
      } catch (error) {
        zip.close();
        return reject(error);
      }
    });
    zip.on('end', resolve);
    zip.on('error', () => reject(new Error('invalid_instagram_export_zip')));
    zip.readEntry();
  });

  if (!documents.length) throw new Error('instagram_export_files_missing');
  return parseInstagramExportDocuments(documents, { ownerUsername, maxRecords });
}

module.exports = { parseInstagramExportDocuments, parseInstagramExportZip, usernameFromExportRow };
