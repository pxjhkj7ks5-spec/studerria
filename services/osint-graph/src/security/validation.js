'use strict';

const ENTITY_TYPES = new Set(['PERSON','SOCIAL_ACCOUNT','ORGANIZATION','DOMAIN','WEBSITE','EMAIL','PHONE','LOCATION','POST','PUBLIC_CHANNEL','USERNAME','DOCUMENT','IMAGE','EVENT','OTHER']);
const RELATIONSHIP_TYPES = new Set(['FOLLOWS','FOLLOWED_BY','MUTUAL_FOLLOW','MENTIONS','COMMENTED_ON','COLLABORATED_WITH','LINKED_TO','MEMBER_OF','WORKS_AT','ASSOCIATED_WITH','SAME_USERNAME','SAME_DOMAIN','COMMON_CONNECTION','OWNS','USES','FOUNDED','TAGGED','COMMENTED','LOCATED_AT','PARTICIPATED_IN','SAME_PERSON_AS','POSSIBLY_SAME_PERSON_AS','RELATED_TO','OTHER']);

function cleanText(value, { max = 500, required = false } = {}) {
  const text = String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (required && !text) throw new Error('required_text_missing');
  if (text.length > max) throw new Error('text_too_long');
  return text;
}

function cleanUsername(value) {
  const username = cleanText(value, { max: 160, required: true }).replace(/^@/, '');
  if (!/^[a-zA-Z0-9_.-]{1,160}$/.test(username)) throw new Error('invalid_username');
  return username;
}

function cleanPublicUrl(value, { required = false } = {}) {
  const text = cleanText(value, { max: 2048, required });
  if (!text) return null;
  let url;
  try { url = new URL(text); } catch (_error) { throw new Error('invalid_url'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('invalid_url');
  return url.toString();
}

function neutralizeSpreadsheetFormula(value) {
  const text = cleanText(value, { max: 500 });
  return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
}

function safeMetadata(value, { depth = 0, counter = { count: 0 }, maxArray = 500, maxKeys = 5000 } = {}) {
  if (depth > 10) throw new Error('metadata_too_deep');
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
    if (typeof value === 'string') { if (value.length > 4000) throw new Error('text_too_long'); return value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim(); }
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > maxArray) throw new Error('metadata_too_large');
    return value.map((item) => safeMetadata(item, { depth: depth + 1, counter, maxArray, maxKeys }));
  }
  if (typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) throw new Error('invalid_metadata');
  const output = {};
  for (const [key, item] of Object.entries(value)) {
    counter.count += 1;
    if (counter.count > maxKeys) throw new Error('metadata_too_large');
    const safeKey = cleanText(key, { max: 100, required: true });
    if (['__proto__', 'prototype', 'constructor'].includes(safeKey)) throw new Error('invalid_metadata_key');
    output[safeKey] = safeMetadata(item, { depth: depth + 1, counter, maxArray, maxKeys });
  }
  return output;
}

function normalizeEntityInput(input = {}) {
  const type = String(input.type || 'OTHER').trim().toUpperCase();
  if (!type || type.length > 80 || /[\u0000-\u001f]/.test(type)) throw new Error('invalid_entity_type');
  const username = (input.username || input.metadata?.username) ? cleanText(input.username || input.metadata.username, { max: 160 }) : '';
  const platform = (input.platform || input.metadata?.platform) ? cleanText(input.platform || input.metadata.platform, { max: 40 }).toLowerCase() : '';
  const displayName = cleanText(input.display_name || input.displayName || input.name || username || input.canonical_name, { max: 500 });
  if (!displayName) throw new Error('required_text_missing');
  const canonicalName = cleanText(input.canonical_name || input.canonicalName || `${platform ? `${platform}:` : ''}${username || displayName}`.toLowerCase(), { max: 500, required: true });
  return {
    externalId: cleanText(input.id || input.external_id || input.externalId || canonicalName, { max: 500, required: true }),
    type,
    canonicalName,
    displayName,
    platform: platform || null,
    username: username || null,
    profileUrl: cleanPublicUrl(input.url || input.profile_url || input.profileUrl || input.metadata?.url || '', { required: false }),
    bio: cleanText(input.bio || '', { max: 500 }),
    metadata: safeMetadata(input.metadata && typeof input.metadata === 'object' ? input.metadata : {}),
  };
}

function normalizeRelationshipInput(input = {}) {
  const type = String(input.type || input.relationship_type || 'OTHER').trim().toUpperCase();
  if (!type || type.length > 80 || /[\u0000-\u001f]/.test(type)) throw new Error('invalid_relationship_type');
  const source = cleanText(input.source || input.source_id || input.source_entity_id, { max: 500, required: true });
  const target = cleanText(input.target || input.target_id || input.target_entity_id, { max: 500, required: true });
  if (source === target) throw new Error('self_relationship');
  const weight = Number(input.weight ?? 1);
  const confidence = Number(input.confidence ?? 1);
  if (!Number.isFinite(weight) || weight < 0 || weight > 100000) throw new Error('invalid_weight');
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) throw new Error('invalid_confidence');
  const status = input.epistemic_status || input.status || 'HYPOTHESIS';
  if (!['FACT','INFERENCE','HYPOTHESIS'].includes(status)) throw new Error('invalid_epistemic_status');
  return {
    status,
    source,
    target,
    type,
    weight,
    confidence,
    explanation: cleanText(input.explanation || input.notes || input.metadata?.notes || '', { max: 4000 }),
    sourceUrl: cleanPublicUrl(input.source_url || input.sourceUrl || '', { required: false }),
    metadata: safeMetadata({ ...(input.metadata && typeof input.metadata === 'object' ? input.metadata : {}), ...(input.label ? { label: cleanText(input.label, { max: 160 }) } : {}) }),
  };
}

module.exports = {
  ENTITY_TYPES,
  RELATIONSHIP_TYPES,
  cleanText,
  cleanUsername,
  cleanPublicUrl,
  neutralizeSpreadsheetFormula,
  safeMetadata,
  normalizeEntityInput,
  normalizeRelationshipInput,
};
