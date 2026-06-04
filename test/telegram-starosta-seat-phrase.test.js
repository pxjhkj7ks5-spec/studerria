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

test('telegram starosta seat phrase sends the photo caption response', () => {
  const phrasesBlock = extractBlock(
    /const STUDERRIA_TG_STAROSTA_SEAT_PHRASES = \[/,
    /async function handleStuderriaTelegramAuthorizedPhraseReply/
  );
  assert.match(phrasesBlock, /'де староста'/);
  assert.match(phrasesBlock, /'а де староста'/);
  assert.match(phrasesBlock, /'де староста курсу'/);
  assert.match(phrasesBlock, /'хто в нас староста'/);
  assert.match(phrasesBlock, /'старосту бачили'/);
  assert.match(phrasesBlock, /STUDERRIA_TG_STAROSTA_SEAT_PHRASE_SET\.has\(text\)/);

  const handlerBlock = extractBlock(
    /async function handleStuderriaTelegramStarostaSeatPhrase/,
    /async function handleStuderriaTelegramMeetingPhrase/
  );
  assert.match(handlerBlock, /const caption = 'пачотне місце старости'/);
  assert.match(handlerBlock, /sendStuderriaTelegramPhoto/);
  assert.match(handlerBlock, /studerriaTelegramStarostaSeatPhotoFile/);
});

test('telegram starosta seat phrase is handled before generic authorized replies', () => {
  const updateBlock = extractBlock(
    /async function handleStuderriaTelegramBotUpdate/,
    /const callbackQuery = update && update\.callback_query/
  );
  assert.match(updateBlock, /isStuderriaTelegramStarostaSeatPhrase\(message\)/);
  assert.ok(
    updateBlock.indexOf('isStuderriaTelegramStarostaSeatPhrase(message)')
      < updateBlock.indexOf('getStuderriaTelegramAuthorizedPhraseReply(message)')
  );
});
