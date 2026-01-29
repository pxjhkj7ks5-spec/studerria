const fs = require('fs');
const path = require('path');

const versionFile = path.join(__dirname, '..', 'version.json');

function parseVersion(value) {
  const parts = value.split('.').map((p) => Number(p));
  if (parts.length !== 3 || parts.some((p) => Number.isNaN(p))) {
    throw new Error(`Invalid version: ${value}`);
  }
  return parts;
}

function formatVersion([major, minor, patch]) {
  return `${major}.${minor}.${patch}`;
}

function bumpVersion(current, mode) {
  let [major, minor, patch] = parseVersion(current);
  if (mode === 'release') {
    return '1.0.0';
  }
  if (mode === 'minor') {
    minor += 1;
    patch = 0;
    return formatVersion([major, minor, patch]);
  }
  if (mode === 'patch') {
    patch += 1;
    return formatVersion([major, minor, patch]);
  }
  throw new Error(`Unknown mode: ${mode}`);
}

const mode = process.argv[2] || 'patch';
const current = JSON.parse(fs.readFileSync(versionFile, 'utf8')).version;
const next = bumpVersion(current, mode);
fs.writeFileSync(versionFile, JSON.stringify({ version: next }, null, 2) + '\n', 'utf8');
console.log(`Version updated: ${current} -> ${next}`);
