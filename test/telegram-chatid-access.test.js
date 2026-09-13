const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');

test('/chatid grants registered starosta access without opening free-text aliases', () => {
  const permissionStart = source.indexOf('async function canShowStuderriaTelegramChatId');
  const permissionEnd = source.indexOf('async function handleStuderriaTelegramChatIdCommand', permissionStart);
  const permissionBlock = source.slice(permissionStart, permissionEnd);
  assert.match(permissionBlock, /getStuderriaTelegramActorContext/);
  assert.match(permissionBlock, /context\.roleKeys\.includes\('starosta'\)/);
  assert.match(permissionBlock, /message\.sender_chat/);

  const dispatchStart = source.indexOf("parsedCommand.command === 'chatid'");
  const dispatchBlock = source.slice(dispatchStart, dispatchStart + 600);
  assert.match(dispatchBlock, /allowStarosta:\s*Boolean\(parsedCommand && parsedCommand\.command === 'chatid'\)/);
});

test('Telegram command menus describe /chatid for dev and starosta', () => {
  assert.equal((source.match(/Dev\/староста: показати ID чату/g) || []).length, 2);
});
