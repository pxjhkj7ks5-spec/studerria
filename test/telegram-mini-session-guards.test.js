const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const appSource = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');

function extractBlock(startPattern, nextPattern) {
  const start = appSource.search(startPattern);
  assert.notEqual(start, -1, `missing block start: ${startPattern}`);
  const rest = appSource.slice(start);
  const next = rest.slice(1).search(nextPattern);
  assert.notEqual(next, -1, `missing block end: ${nextPattern}`);
  return rest.slice(0, next + 1);
}

test('telegram mini protected middleware validates session against database', () => {
  const block = extractBlock(
    /async function requireTelegramMiniStudent/,
    /async function ensureTelegramMiniSetupForPage/
  );
  assert.match(block, /await ensureDbReady\(\)/);
  assert.match(block, /await validateTelegramMiniSession\(req\)/);
  assert.match(block, /return res\.redirect\('\/studerria-tg\/register'\)/);
});

test('telegram mini entry routes do not trust stale cookie sessions', () => {
  const entryBlock = extractBlock(
    /app\.get\('\/studerria-tg'/,
    /app\.post\('\/studerria-tg\/auth\/init'/
  );
  assert.match(entryBlock, /await validateTelegramMiniSession\(req\)/);
  assert.doesNotMatch(entryBlock, /if \(canUseTelegramMiniSession\(req\)\)/);

  const loginBlock = extractBlock(
    /app\.get\('\/studerria-tg\/login'/,
    /app\.post\('\/studerria-tg\/login'/
  );
  assert.match(loginBlock, /await validateTelegramMiniSession\(req\)/);
  assert.doesNotMatch(loginBlock, /if \(canUseTelegramMiniSession\(req\)\)/);
});

test('telegram mini auth init clears any stale authenticated user when telegram link is missing', () => {
  const block = extractBlock(
    /app\.post\('\/studerria-tg\/auth\/init'/,
    /app\.get\('\/studerria-tg\/login'/
  );
  assert.match(block, /if \(req\.session && req\.session\.user\)/);
  assert.match(block, /clearTelegramMiniAuthenticatedUser\(req\)/);
});
