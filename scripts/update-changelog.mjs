import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const rootDir = process.cwd();
const changelogPath = path.join(rootDir, 'changelog.json');
const versionPath = path.join(rootDir, 'version.json');

const versionInfo = JSON.parse(readFileSync(versionPath, 'utf8'));
const changelog = JSON.parse(readFileSync(changelogPath, 'utf8'));
const items = Array.isArray(changelog.items) ? changelog.items : [];
const currentVersion = String(versionInfo.version || '').trim();
if (!currentVersion) {
  throw new Error('version.json is missing "version"');
}

const today = new Date().toISOString().slice(0, 10);
const latestLoggedVersion = items[0] && typeof items[0].version === 'string'
  ? String(items[0].version).trim()
  : '';

if (latestLoggedVersion === currentVersion) {
  console.log(`Changelog already up to date for version ${currentVersion}`);
  process.exit(0);
}

const raw = execSync('git log --pretty=format:%H%x1f%s%x1f%cI', {
  cwd: rootDir,
  encoding: 'utf8',
});

const commitRows = raw
  .split('\n')
  .map((line) => {
    const [hash, message, committedAt] = line.split('\u001f');
    return {
      hash,
      message: String(message || '').trim(),
      committedAt,
    };
  })
  .filter((row) => row.message);

const stopMarkers = [
  latestLoggedVersion ? `update release notes for ${latestLoggedVersion}` : '',
  latestLoggedVersion ? `release notes for ${latestLoggedVersion}` : '',
].filter(Boolean);

const releaseItems = [];
for (const row of commitRows) {
  const normalizedMessage = row.message.toLowerCase();
  if (stopMarkers.some((marker) => normalizedMessage.includes(marker.toLowerCase()))) {
    break;
  }
  if (normalizedMessage.startsWith('merge ')) continue;
  if (normalizedMessage.includes('chore(changelog): update release notes')) continue;
  if (normalizedMessage.includes('chore: update changelog')) continue;
  releaseItems.push(row.message);
}

const uniqueReleaseItems = Array.from(new Set(releaseItems));
const nextItems = uniqueReleaseItems.length
  ? uniqueReleaseItems
  : [`chore(release): update application to ${currentVersion}`];

const nextEntry = {
  version: currentVersion,
  date: today,
  items: nextItems,
};

const nextChangelog = {
  items: [nextEntry, ...items],
};

writeFileSync(changelogPath, `${JSON.stringify(nextChangelog, null, 2)}\n`);
console.log(`Changelog updated for version ${currentVersion}`);

