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

test('telegram authorized phrase replies include custom prompts', () => {
  const phraseBlock = extractBlock(
    /const STUDERRIA_TG_AUTHORIZED_PHRASE_REPLIES = new Map\(\[/,
    /function getStuderriaTelegramAuthorizedPhraseReply/
  );
  assert.match(phraseBlock, /\['романенко', 'хто саме\?'\]/);
  assert.match(phraseBlock, /\['денис', 'посол україни в ізраїлі'\]/);
  assert.match(phraseBlock, /\['юля', 'тігруля🍓💅'\]/);
});
