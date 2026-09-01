const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const registerSubjectHelpers = require('../lib/registerSubjects');
const { createTelegramActionTokenStore } = require('../lib/telegramActionTokens');
const { createStuderriaTelegramSubjectReset, CONFIRM_TTL_MS } = require('../lib/studerriaTelegramSubjectReset');

function fixture(overrides = {}) {
  let time = 1000;
  const devIds = new Set(['123', '456']);
  const calls = { summaries: 0, resets: [], sent: [], edits: [], answers: [], errors: [] };
  const actions = createTelegramActionTokenStore({ now: () => time });
  const handler = createStuderriaTelegramSubjectReset({
    now: () => time,
    isDevUser: (user) => devIds.has(String(user.id)),
    actions,
    getSummary: async () => { calls.summaries++; return { users: 3, selections: 4, optouts: 2 }; },
    resetAll: async (actor) => {
      calls.resets.push(actor);
      return { users: 3, selections: 4, optouts: 2, auditId: 99 };
    },
    sendMessage: async (...args) => { calls.sent.push(args); },
    editMessage: async (...args) => { calls.edits.push(args); },
    answerCallback: async (...args) => { calls.answers.push(args); },
    logger: { error: (...args) => calls.errors.push(args) },
    ...overrides,
  });
  const message = { from: { id: 123 }, chat: { id: 123, type: 'private' }, text: '/resetsubjects' };
  const callback = (data, changes = {}) => ({ id: 'callback', data, from: message.from, message, ...changes });
  async function preview() {
    await handler.handleCommand(message);
    return calls.sent.at(-1)[2].replyMarkup.inline_keyboard[0].map((button) => button.callback_data);
  }
  return { handler, calls, actions, devIds, message, callback, preview, advance: (ms) => { time += ms; } };
}

test('reset command rejects non-dev roles, spoofed usernames, bots and anonymous senders before reading data', async () => {
  const f = fixture();
  for (const from of [undefined, { id: 789, role: 'admin' }, { id: 789, role: 'starosta' }, { id: 789, role: 'student' }, { id: 789, username: 'dev' }, { id: 123, is_bot: true }]) {
    await f.handler.handleCommand({ ...f.message, from });
  }
  await f.handler.handleCommand({ ...f.message, sender_chat: { id: -10 } });
  assert.equal(f.calls.summaries, 0);
  assert.equal(f.calls.resets.length, 0);
  assert.ok(f.calls.sent.every(([, text]) => text.includes('Недостатньо прав')));
});

test('even dev must open the reset in their own private chat', async () => {
  const f = fixture();
  for (const chat of [{ id: -10, type: 'group' }, { id: -20, type: 'supergroup' }, { id: 456, type: 'private' }]) {
    await f.handler.handleCommand({ ...f.message, chat });
  }
  assert.equal(f.calls.summaries, 0);
  assert.equal(f.calls.resets.length, 0);
});

test('dev preview shows scope and counts without resetting; confirmation is one-shot', async () => {
  const f = fixture();
  const [confirm] = await f.preview();
  assert.match(f.calls.sent[0][1], /3 користувачів, 4 виборів груп і 2/);
  assert.match(f.calls.sent[0][1], /всіх курсів/);
  assert.equal(f.calls.resets.length, 0);
  await Promise.all([f.handler.handleCallback(f.callback(confirm)), f.handler.handleCallback(f.callback(confirm))]);
  assert.deepEqual(f.calls.resets, [{ actorTelegramId: '123' }]);
  assert.match(f.calls.edits.at(-1)[1], /#99/);
  assert.equal(f.actions.getActionPayload(confirm), null);
});

test('confirmation rechecks dev access and binds both actor and private chat', async () => {
  const f = fixture();
  const [confirm] = await f.preview();
  const attempts = [
    { from: { id: 789, role: 'admin' } },
    { from: { id: 123, is_bot: true } },
    { from: { id: 456 } },
    { message: { chat: { id: 456, type: 'private' } } },
    { message: { chat: { id: 123, type: 'group' } } },
    { message: undefined },
  ];
  for (const attempt of attempts) await f.handler.handleCallback(f.callback(confirm, attempt));
  f.devIds.delete('123');
  await f.handler.handleCallback(f.callback(confirm));
  assert.equal(f.calls.resets.length, 0);
  assert.ok(f.actions.getActionPayload(confirm));
  f.devIds.add('123');
  await f.handler.handleCallback(f.callback(confirm));
  assert.equal(f.calls.resets.length, 1);
});

test('cancel invalidates the matching confirmation too', async () => {
  const f = fixture();
  const [confirm, cancel] = await f.preview();
  await f.handler.handleCallback(f.callback(cancel));
  await f.handler.handleCallback(f.callback(confirm));
  assert.equal(f.calls.resets.length, 0);
  assert.match(f.calls.edits[0][1], /Скидання скасовано/);
});

test('confirmation expires at five minutes and fabricated tokens cannot reset', async () => {
  const f = fixture();
  const [confirm] = await f.preview();
  f.advance(CONFIRM_TTL_MS);
  await f.handler.handleCallback(f.callback(confirm));
  await f.handler.handleCallback(f.callback('stb:forged'));
  assert.equal(f.calls.resets.length, 0);
  assert.ok(f.calls.answers.every(([, text]) => /застаріл/.test(text)));
});

test('another confirmation cannot start a reset while one is running', async () => {
  let finish;
  let runs = 0;
  const result = new Promise((resolve) => { finish = resolve; });
  const f = fixture({ resetAll: async () => { runs++; return result; } });
  const [first] = await f.preview();
  const [second] = await f.preview();
  const pending = f.handler.handleCallback(f.callback(first));
  await f.handler.handleCallback(f.callback(second));
  assert.equal(runs, 1);
  assert.match(f.calls.answers.at(-1)[1], /вже виконується/);
  finish({ users: 3, selections: 4, optouts: 2, auditId: 99 });
  await pending;
});

test('a failed transaction consumes the confirmation and reports failure, not success', async () => {
  let runs = 0;
  const f = fixture({ resetAll: async () => { runs++; throw new Error('database failure'); } });
  const [confirm] = await f.preview();
  await f.handler.handleCallback(f.callback(confirm));
  await f.handler.handleCallback(f.callback(confirm));
  assert.equal(runs, 1);
  assert.match(f.calls.edits[0][1], /Транзакцію скасовано/);
});

test('notification errors after commit never retry the reset', async () => {
  const f = fixture({
    onReset: async () => { throw new Error('broadcast failure'); },
    editMessage: async () => { throw new Error('telegram failure'); },
  });
  const [confirm] = await f.preview();
  await f.handler.handleCallback(f.callback(confirm));
  await f.handler.handleCallback(f.callback(confirm));
  assert.equal(f.calls.resets.length, 1);
  assert.equal(f.calls.errors.length, 2);
});

test('empty data and summary failures do not offer a destructive button', async () => {
  for (const getSummary of [async () => ({ users: 0, selections: 0, optouts: 0 }), async () => { throw new Error('offline'); }]) {
    const f = fixture({ getSummary });
    await f.handler.handleCommand(f.message);
    assert.equal(f.calls.resets.length, 0);
    assert.equal(f.calls.sent[0][2], undefined);
    assert.match(f.calls.sent[0][1], /Нічого/);
  }
});

test('bot wires command and callback to guarded handler and exposes the menu only to dev IDs', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  assert.match(source, /parsedCommand\.command === 'resetsubjects'[\s\S]*?studerriaTelegramSubjectReset\.handleCommand\(message\)/);
  assert.match(source, /String\(payload\.flow \|\| ''\) === RESET_FLOW[\s\S]*?studerriaTelegramSubjectReset\.handleCallback\(callbackQuery\)/);
  assert.match(source, /isDevUser: isStuderriaTelegramDevUser/);
  const menu = source.slice(source.indexOf('const STUDERRIA_TG_PRIVATE_BOT_COMMANDS'), source.indexOf('async function registerStuderriaTelegramBotCommands'));
  assert.doesNotMatch(menu, /resetsubjects/);
  assert.match(source, /for \(const devId of getStuderriaTelegramDevIds\(\)\)[\s\S]*?scope: \{ type: 'chat', chat_id: devId \}[\s\S]*?command: 'resetsubjects'/);
});

test('mini app rechecks choices after reset even when its session was previously complete', async () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  const extract = (name, next) => source.slice(source.indexOf(`async function ${name}(`), source.indexOf(`async function ${next}(`));
  let selected = true;
  const context = vm.createContext({
    db: { get: async () => ({ id: 10, group_id: 1 }) },
    usersHasIsActive: true,
    getAcademicV2Store: () => ({}),
    academicV2StudentHelpers: { loadStudentSubjectCatalog: async () => ({
      scope: { resolved_via: 'group_id' },
      term: { id: 1 },
      subjects: [{ id: 21, name: 'Предмет', group_count: 2, is_required: true, selected_group: selected ? 2 : null, opted_out: false }],
    }) },
    autoAssignTelegramMiniRequiredSubjects: async () => false,
    registerSubjectHelpers,
    saveRequestSession: async () => {},
  });
  vm.runInContext(extract('loadTelegramMiniSetupState', 'loadTelegramMiniRegistrationGroups'), context);
  vm.runInContext(extract('ensureTelegramMiniSetupForPage', 'validateTelegramMiniInitData'), context);
  const req = { session: { telegramMiniSetupCompleteUserId: 10 } };
  assert.equal((await context.ensureTelegramMiniSetupForPage(req, 10)).nextStep, 'complete');
  selected = false;
  const afterReset = await context.ensureTelegramMiniSetupForPage(req, 10);
  assert.equal(afterReset.nextStep, 'subjects');
  assert.equal(afterReset.status, 'missing_subject_choices');
  assert.equal(req.session.telegramMiniSetupCompleteUserId, null);
  const route = source.slice(source.indexOf("app.get('/studerria-tg/schedule'"), source.indexOf("app.get('/studerria-tg/schedule'") + 800);
  assert.match(route, /ensureTelegramMiniSetupForPage/);
  assert.match(route, /res\.redirect\(`\/studerria-tg\/register\?step=\$\{setupState\.nextStep\}`\)/);
});
