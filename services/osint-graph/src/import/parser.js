'use strict';

const { parse } = require('csv-parse/sync');
const { normalizeEntityInput, normalizeRelationshipInput, neutralizeSpreadsheetFormula } = require('../security/validation');
const { parseInstagramExportZip } = require('./instagramExport');

function sanitizeCsvEntityRow(row) {
  const output = { ...row };
  for (const key of ['name', 'display_name', 'displayName', 'bio']) {
    if (Object.hasOwn(output, key)) output[key] = neutralizeSpreadsheetFormula(output[key]);
  }
  return output;
}

function parseJsonDataset(buffer, { maxRecords = 5000 } = {}) {
  let value;
  try { value = JSON.parse(buffer.toString('utf8')); } catch (_error) { throw new Error('invalid_json'); }
  if (!value || !Array.isArray(value.entities) || !Array.isArray(value.relationships)) throw new Error('invalid_dataset_shape');
  if (value.entities.length + value.relationships.length > maxRecords) throw new Error('too_many_records');
  return {
    entities: value.entities.map(normalizeEntityInput),
    relationships: value.relationships.map(normalizeRelationshipInput),
  };
}

function parseCsvBuffer(buffer, { maxRecords = 5000 } = {}) {
  let rows;
  try {
    rows = parse(buffer, { columns: true, bom: true, skip_empty_lines: true, trim: true, max_record_size: 64 * 1024 });
  } catch (_error) {
    throw new Error('invalid_csv');
  }
  if (rows.length > maxRecords) throw new Error('too_many_records');
  if (!rows.length) return { entities: [], relationships: [] };
  for (const row of rows) if (row.metadata) { try { row.metadata = JSON.parse(row.metadata); } catch { throw new Error('invalid_metadata'); } }
  const keys = new Set(Object.keys(rows[0]).map((key) => key.toLowerCase()));
  if ((keys.has('source') && keys.has('target')) || (keys.has('source_entity_id') && keys.has('target_entity_id'))) return { entities: [], relationships: rows.map(normalizeRelationshipInput) };
  if (keys.has('type') && (keys.has('name') || keys.has('username') || keys.has('canonical_name'))) {
    return { entities: rows.map((row) => normalizeEntityInput(sanitizeCsvEntityRow(row))), relationships: [] };
  }
  throw new Error('unknown_csv_shape');
}

function combineDatasets(datasets, { maxRecords = 5000 } = {}) {
  const combined = datasets.reduce((result, dataset) => ({
    entities: result.entities.concat(dataset.entities || []),
    relationships: result.relationships.concat(dataset.relationships || []),
  }), { entities: [], relationships: [] });
  if (combined.entities.length + combined.relationships.length > maxRecords) throw new Error('too_many_records');
  return combined;
}

async function parseImportFiles(files, options = {}) {
  if (!Array.isArray(files) || !files.length) throw new Error('import_file_required');
  const zipFiles = files.filter((file) => String(file.originalname || '').toLowerCase().endsWith('.zip'));
  if (zipFiles.length) {
    if (files.length !== 1) throw new Error('instagram_export_zip_must_be_single');
    return parseInstagramExportZip(zipFiles[0].buffer, options);
  }
  return combineDatasets(files.map((file) => {
    const name = String(file.originalname || '').toLowerCase();
    const mime = String(file.mimetype || '').toLowerCase();
    if (name.endsWith('.json') || mime === 'application/json') return parseJsonDataset(file.buffer, options);
    if (name.endsWith('.csv') || ['text/csv', 'application/csv', 'text/plain'].includes(mime)) return parseCsvBuffer(file.buffer, options);
    throw new Error('unsupported_import_type');
  }), options);
}

module.exports = { parseJsonDataset, parseCsvBuffer, combineDatasets, parseImportFiles };
