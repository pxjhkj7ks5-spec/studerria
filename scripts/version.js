const fs = require('fs');
const path = require('path');

const versionFile = path.join(__dirname, '..', 'version.json');

function parseVersion(value) {
  const raw = value.split('.');
  const parts = raw.map((p) => Number(p));
  if (parts.length !== 3 || parts.some((p) => Number.isNaN(p))) {
    throw new Error(`Invalid version: ${value}`);
  }
  const widths = raw.map((p) => p.length);
  return { parts, widths };
}

function pad(num, width) {
  return String(num).padStart(width, '0');
}

function formatVersion([major, minor, patch], widths) {
  const [wMajor, wMinor, wPatch] = widths;
  return `${pad(major, wMajor)}.${pad(minor, wMinor)}.${pad(patch, wPatch)}`;
}

function bumpVersion(current, mode) {
  const { parts, widths } = parseVersion(current);
  let [major, minor, patch] = parts;
  if (mode === 'release') {
    return formatVersion([1, 0, 0], widths);
  }
  if (mode === 'minor') {
    minor += 1;
    patch = 0;
    return formatVersion([major, minor, patch], widths);
  }
  if (mode === 'patch') {
    patch += 1;
    return formatVersion([major, minor, patch], widths);
  }
  throw new Error(`Unknown mode: ${mode}`);
}

const mode = process.argv[2] || 'patch';
const current = JSON.parse(fs.readFileSync(versionFile, 'utf8')).version;
const next = bumpVersion(current, mode);
fs.writeFileSync(versionFile, JSON.stringify({ version: next }, null, 2) + '\n', 'utf8');
console.log(`Version updated: ${current} -> ${next}`);
