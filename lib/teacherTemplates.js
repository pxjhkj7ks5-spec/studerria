function cleanCompactText(value, maxLength = 160) {
  return String(value || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, Math.max(1, Number(maxLength) || 1));
}

function normalizeHomeworkTemplateTitleInput(rawTitle, fallbackDescription, fallbackSubjectName) {
  const explicitTitle = cleanCompactText(rawTitle, 160);
  if (explicitTitle) {
    return explicitTitle;
  }
  const fallbackLine = cleanCompactText(String(fallbackDescription || '').split('\n')[0], 160);
  if (fallbackLine) {
    return fallbackLine;
  }
  const subjectLabel = cleanCompactText(fallbackSubjectName, 120);
  if (subjectLabel) {
    return `${subjectLabel} homework`.slice(0, 160);
  }
  return 'Homework template';
}

function normalizeTemplateAssetIds(rawValue, limit = 24) {
  const values = Array.isArray(rawValue)
    ? rawValue
    : (typeof rawValue === 'string' ? rawValue.split(',') : [rawValue]);
  return Array.from(new Set(values
    .map((value) => Number(value))
    .filter((value) => Number.isInteger(value) && value > 0)))
    .slice(0, Math.max(1, Number(limit) || 1));
}

function buildAppliedHomeworkAssetIds({ templateAssetIds = [], uploadedAssetIds = [] } = {}) {
  const ordered = [];
  const seen = new Set();
  normalizeTemplateAssetIds(templateAssetIds, 64).forEach((assetId) => {
    if (seen.has(assetId)) return;
    seen.add(assetId);
    ordered.push(assetId);
  });
  normalizeTemplateAssetIds(uploadedAssetIds, 64).forEach((assetId) => {
    if (seen.has(assetId)) return;
    seen.add(assetId);
    ordered.push(assetId);
  });
  return ordered;
}

function buildAssetDisplayName(assetRow = {}) {
  const explicitName = cleanCompactText(assetRow.name, 160);
  if (explicitName) return explicitName;
  const originalName = cleanCompactText(assetRow.original_name, 160);
  if (originalName) return originalName;
  return 'Attachment';
}

module.exports = {
  normalizeHomeworkTemplateTitleInput,
  normalizeTemplateAssetIds,
  buildAppliedHomeworkAssetIds,
  buildAssetDisplayName,
};
