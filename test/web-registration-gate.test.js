const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ejs = require('ejs');

const rootDir = path.join(__dirname, '..');

test('public web registration is closed by default and gated on both routes', () => {
  const source = fs.readFileSync(path.join(rootDir, 'app.js'), 'utf8');
  assert.match(source, /web_registration_enabled:\s*false/);

  const getStart = source.indexOf("app.get('/register'");
  const postStart = source.indexOf("app.post('/register'");
  const nextRoute = source.indexOf("app.get('/register/teacher-subjects'", postStart);
  const getBlock = source.slice(getStart, postStart);
  const postBlock = source.slice(postStart, nextRoute);

  assert.match(getBlock, /settingsCache\.web_registration_enabled !== true/);
  assert.match(getBlock, /render\('register-closed'/);
  assert.match(postBlock, /settingsCache\.web_registration_enabled !== true/);
  assert.match(postBlock, /status\(403\)\.render\('register-closed'/);
});

test('Telegram registration route remains separate from the web gate', () => {
  const source = fs.readFileSync(path.join(rootDir, 'app.js'), 'utf8');
  const routeStart = source.indexOf("app.post('/studerria-tg/register'");
  assert.ok(routeStart > 0);
  const routeBlock = source.slice(routeStart, routeStart + 5000);
  assert.doesNotMatch(routeBlock, /web_registration_enabled/);
});

test('admin exposes the registration toggle and closed page keeps login available', async () => {
  const adminView = fs.readFileSync(path.join(rootDir, 'views', 'admin.ejs'), 'utf8');
  assert.match(adminView, /name="web_registration_enabled"/);
  assert.match(adminView, />Закрита</);

  const html = await ejs.renderFile(path.join(rootDir, 'views', 'register-closed.ejs'), {
    lang: 'uk',
    appVersion: '0.0.0',
    changelog: [],
    t: (key) => key,
  });
  assert.match(html, /Реєстрацію закрито/);
  assert.match(html, /href="\/login"/);
  assert.match(html, /Telegram-бот/);
});
