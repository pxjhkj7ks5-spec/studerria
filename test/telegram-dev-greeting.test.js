const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  STUDERRIA_TG_GREETING_TEMPLATES,
  buildStuderriaTelegramGreeting,
  formatGreetingNameList,
  getStuderriaTelegramGreetingTarget,
  parseStuderriaTelegramGreetingCommand,
} = require('../lib/studerriaTelegramGreeting');

const appSource = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
const dockerComposeSource = fs.readFileSync(path.join(__dirname, '..', 'docker', 'local', 'docker-compose.yml'), 'utf8');

test('telegram dev greeting parses one or several names after trigger', () => {
  assert.deepEqual(
    parseStuderriaTelegramGreetingCommand('Привітай: Гліб, Артем, Нестор'),
    { names: ['Гліб', 'Артем', 'Нестор'] }
  );
  assert.deepEqual(
    parseStuderriaTelegramGreetingCommand('привітай:  Марія  '),
    { names: ['Марія'] }
  );
  assert.equal(parseStuderriaTelegramGreetingCommand('привіт'), null);
  assert.equal(parseStuderriaTelegramGreetingCommand('Привітай:'), null);
});

test('telegram dev greeting formats name list naturally', () => {
  assert.equal(formatGreetingNameList(['Гліб']), 'Гліб');
  assert.equal(formatGreetingNameList(['Гліб', 'Артем']), 'Гліб і Артем');
  assert.equal(formatGreetingNameList(['Гліб', 'Артем', 'Нестор']), 'Гліб, Артем і Нестор');
});

test('telegram dev greeting builds deterministic template when random is injected', () => {
  const greeting = buildStuderriaTelegramGreeting(['Гліб', 'Артем', 'Нестор'], () => 0);
  assert.match(greeting, /^Гліб, Артем і Нестор, з днем народження легенди!!!/);
  assert.match(greeting, /Студерія передає/);
  assert.match(greeting, /без зайвого стресу/);
});

test('telegram dev greeting keeps a broad random template pool', () => {
  assert.ok(STUDERRIA_TG_GREETING_TEMPLATES.length >= 20);
});

test('telegram dev greeting target comes from explicit env guard', () => {
  assert.deepEqual(getStuderriaTelegramGreetingTarget({
    STUDERRIA_TG_DEV_GREETING_ENABLED: 'true',
    STUDERRIA_TG_DEV_GREETING_TARGET_CHAT_ID: '-100123',
    STUDERRIA_TG_DEV_GREETING_TARGET_THREAD_ID: '77',
  }), {
    enabled: true,
    chatId: '-100123',
    threadId: 77,
  });

  assert.deepEqual(getStuderriaTelegramGreetingTarget({
    STUDERRIA_TG_DEV_GREETING_ENABLED: 'false',
    STUDERRIA_TG_DEV_GREETING_TARGET_CHAT_ID: '-100123',
    STUDERRIA_TG_DEV_GREETING_TARGET_THREAD_ID: 'abc',
  }), {
    enabled: false,
    chatId: '-100123',
    threadId: null,
  });
});

test('telegram dev greeting uses preview confirmation before sending', () => {
  assert.match(appSource, /Попередній перегляд привітання/);
  assert.match(appSource, /flow: 'greeting_confirm'/);
  assert.match(appSource, /text: 'Надіслати'/);
  assert.match(appSource, /handleStuderriaTelegramGreetingConfirmCallback/);
});

test('telegram dev greeting env is passed into the local app container', () => {
  assert.match(dockerComposeSource, /STUDERRIA_TG_DEV_GREETING_ENABLED: \$\{STUDERRIA_TG_DEV_GREETING_ENABLED:-false\}/);
  assert.match(dockerComposeSource, /STUDERRIA_TG_DEV_GREETING_TARGET_CHAT_ID: \$\{STUDERRIA_TG_DEV_GREETING_TARGET_CHAT_ID:-\}/);
  assert.match(dockerComposeSource, /STUDERRIA_TG_DEV_GREETING_TARGET_THREAD_ID: \$\{STUDERRIA_TG_DEV_GREETING_TARGET_THREAD_ID:-\}/);
});
