const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const appSource = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');

test('toggletag is a private command available to every Telegram user', () => {
  const privateCommands = appSource.slice(
    appSource.indexOf('const STUDERRIA_TG_PRIVATE_BOT_COMMANDS'),
    appSource.indexOf('const STUDERRIA_TG_GROUP_BOT_COMMANDS')
  );
  const groupCommands = appSource.slice(
    appSource.indexOf('const STUDERRIA_TG_GROUP_BOT_COMMANDS'),
    appSource.indexOf('async function registerStuderriaTelegramBotCommands')
  );
  assert.match(privateCommands, /command: 'toggletag'/);
  assert.doesNotMatch(groupCommands, /command: 'toggletag'/);
  assert.match(appSource, /parsedCommand\.command === 'toggletag'[\s\S]*?handleStuderriaTelegramTagPreferenceCommand\(message\)/);
  assert.match(appSource, /toggleTagPreference\(telegramId\)/);
  assert.doesNotMatch(
    appSource.slice(
      appSource.indexOf('async function handleStuderriaTelegramTagPreferenceCommand'),
      appSource.indexOf('function buildStuderriaTelegramScheduleChangeNotification')
    ),
    /findStuderriaTelegramUserByActor|isStuderriaTelegramDevUser/
  );
});
