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

test('telegram private bot commands register stable role command names', () => {
  const commandsBlock = extractBlock(
    /const STUDERRIA_TG_PRIVATE_BOT_COMMANDS = \[/,
    /const STUDERRIA_TG_GROUP_BOT_COMMANDS = \[/
  );
  assert.match(commandsBlock, /command: 'addrole'/);
  assert.match(commandsBlock, /command: 'deleterole'/);
});

test('telegram role handlers keep legacy aliases working', () => {
  const handlerBlock = extractBlock(
    /const parsedCommand = parseStuderriaTelegramCommand/,
    /const callbackQuery = update && update\.callback_query/
  );
  assert.match(handlerBlock, /parsedCommand\.command === 'addrole' \|\| parsedCommand\.command === 'giverole'/);
  assert.match(handlerBlock, /parsedCommand\.command === 'deleterole' \|\| parsedCommand\.command === 'removerole'/);
});

test('telegram help presents addrole and deleterole as primary commands', () => {
  const helpBlock = extractBlock(
    /async function sendStuderriaTelegramHelp/,
    /function normalizeStuderriaTelegramFreeText/
  );
  assert.match(helpBlock, /\/addrole starosta @username/);
  assert.match(helpBlock, /\/addrole starosta 123456789/);
  assert.match(helpBlock, /\/deleterole starosta @username/);
  assert.match(helpBlock, /\/deleterole starosta 123456789/);
  assert.match(helpBlock, /Старі aliases: \/giverole і \/removerole теж працюють\./);
});
