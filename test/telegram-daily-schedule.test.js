const test = require('node:test');
const assert = require('node:assert/strict');
const { getDailyScheduleConfig, getKyivClock, shiftDate, getTermWeek, collectDailySchedule,
  buildDailyScheduleText, visibleLength, createDailyScheduleService } = require('../lib/studerriaTelegramDailySchedule');

const course = { course_id: 10, group_id: 20, campus_key: 'kyiv', program_name: 'ПЛЕД', admission_year: 2025, label: 'Київ' };
const term = { id: 30, start_date: '2026-08-31', weeks_count: 15 };
const config = () => getDailyScheduleConfig({ STUDERRIA_TG_DAILY_SCHEDULE_ENABLED: 'true',
  STUDERRIA_TG_DAILY_SCHEDULE_CHAT_ID: '-100111', STUDERRIA_TG_DAILY_SCHEDULE_COURSE_ID: '10' });
const user = (id, extra = {}) => ({ id, group_id: 20, telegram_username: `student_${id}`, full_name: `Студент ${id}`, ...extra });
const row = (extra = {}) => ({ schedule_entry_id: 1, group_subject_id: 100, group_subject_activity_id: 101,
  term_id: 30, subject_name: 'Англійська', class_number: 1, day_of_week: 'Wednesday',
  activity_type: 'lecture', selected_group: 1, group_number: 1, ...extra });

function fixture(users = [user(1)], options = {}) {
  const records = options.records || new Map();
  const sent = [];
  const errors = [];
  const scenarios = options.scenarios || {};
  const current = { date: new Date('2026-09-01T15:00:00Z'), config: config() };
  let loads = 0;
  const state = (person) => ({ scope: { group_id: 20, campus_key: 'kyiv' }, term,
    subjects: [{ group_subject_id: 100, is_selected: true }],
    scheduleRows: [row()], projectionIssues: { has_issues: false }, ...scenarios[person.id]?.state });
  const deps = {
    now: () => current.date, getConfig: () => current.config, hasBotToken: () => true,
    ensureReady: async () => {}, isDevUser: (actor) => actor.id === 99,
    replyMarkup: () => ({ inline_keyboard: [[{ text: 'Мій розклад у Studeri', url: 'https://t.me/example/app' }]] }),
    logger: { error: (...args) => errors.push(args), log: () => {} },
    formatTime: (number) => ({ 1: '08:30-09:50', 2: '10:00-11:20' }[number] || ''),
    store: {
      loadCourse: async () => course,
      loadStudents: async () => { loads += 1; return users; },
      claimDelivery: async (delivery) => {
        if (records.has(delivery.key)) return null;
        const record = { ...delivery, id: records.size + 1, status: 'sending' };
        records.set(delivery.key, record);
        return record;
      },
      finishDelivery: async (id, status, messageId, error) => {
        const record = Array.from(records.values()).find((item) => item.id === id);
        Object.assign(record, { status, messageId, error });
      },
    },
    loadSetup: async (person) => ({ nextStep: 'complete', subjectState: state(person), ...scenarios[person.id]?.setup }),
    loadSchedule: async (person) => {
      if (scenarios[person.id]?.error) throw new Error('database unavailable');
      return state(person);
    },
    sendMessage: async (chatId, text, sendOptions = {}) => {
      sent.push({ chatId, text, options: sendOptions });
      return { message_id: sent.length };
    },
  };
  return { deps, records, sent, errors, current, get loads() { return loads; } };
}

test('configuration defaults are disabled, Kyiv 18:00, 30 seconds; invalid topics fail closed', () => {
  const defaults = getDailyScheduleConfig({});
  assert.equal(defaults.enabled, false);
  assert.equal(defaults.time.label, '18:00');
  assert.equal(defaults.checkIntervalMs, 30000);
  assert.equal(getDailyScheduleConfig({ STUDERRIA_TG_DAILY_SCHEDULE_CHECK_INTERVAL_MS: '300000' }).checkIntervalMs, 60000);
  assert.equal(getDailyScheduleConfig({ STUDERRIA_TG_DAILY_SCHEDULE_THREAD_ID: 'bad' }).invalid, true);
  assert.equal(getDailyScheduleConfig({ STUDERRIA_TG_DAILY_SCHEDULE_COURSE_ID: '2025x' }).invalid, true);
  assert.equal(getDailyScheduleConfig({ STUDERRIA_TG_DAILY_SCHEDULE_TIME: '25:80' }).time.label, '18:00');
});

test('Kyiv date and clock handle summer, winter, midnight and calendar rollover', () => {
  assert.equal(getKyivClock(new Date('2026-09-01T15:00:00Z')).hour, 18);
  assert.equal(getKyivClock(new Date('2026-12-01T16:00:00Z')).hour, 18);
  assert.deepEqual(getKyivClock(new Date('2026-09-01T21:00:00Z')), { dateIso: '2026-09-02', hour: 0, minute: 0 });
  assert.equal(shiftDate('2026-12-31', 1), '2027-01-01');
  assert.equal(shiftDate('2028-02-28', 1), '2028-02-29');
});

test('semester boundaries never clamp an outside date to the first or last week', () => {
  assert.deepEqual(getTermWeek(term, '2026-08-30'), { status: 'outside_term' });
  assert.deepEqual(getTermWeek(term, '2026-08-31'), { status: 'ready', weekNumber: 1 });
  assert.deepEqual(getTermWeek(term, '2026-12-13'), { status: 'ready', weekNumber: 15 });
  assert.deepEqual(getTermWeek(term, '2026-12-14'), { status: 'outside_term' });
  assert.deepEqual(getTermWeek(null, '2026-09-01'), { status: 'unavailable' });
  assert.deepEqual(getTermWeek({ ...term, start_date: '2026-02-31' }, '2026-09-01'), { status: 'unavailable' });
});

test('students share a block only when their entire day matches, regardless of row order', async () => {
  const second = row({ schedule_entry_id: 2, class_number: 2 });
  const f = fixture([user(2), user(1), user(3)], { scenarios: {
    1: { state: { scheduleRows: [row(), second] } },
    2: { state: { scheduleRows: [second, row(), row()] } },
    3: { state: { scheduleRows: [second] } },
  } });
  const digest = await collectDailySchedule(f.deps, course, '2026-09-02');
  assert.equal(digest.blocks.length, 2);
  assert.deepEqual(digest.blocks[0].students.map((person) => person.id), [1, 2]);
  assert.deepEqual(digest.blocks[0].lessons.map((lesson) => lesson.classNumber), [1, 2]);
});

test('shared lectures ignore student subgroup and unselected lectures are excluded', async () => {
  const f = fixture([user(1), user(2)], { scenarios: {
    1: { state: { scheduleRows: [row(), row({ group_subject_id: 200, subject_name: 'Не вибрано', schedule_entry_id: 3 })] } },
    2: { state: { scheduleRows: [row({ selected_group: 3, group_number: 3, group_label: 'Group 3' })] } },
  } });
  const digest = await collectDailySchedule(f.deps, course, '2026-09-02');
  assert.equal(digest.blocks.length, 1);
  assert.equal(digest.blocks[0].students.length, 2);
  const text = buildDailyScheduleText(digest);
  assert.doesNotMatch(text, /Не вибрано|Group 3|Група/);
});

test('different practice events stay separate; a multi-group event stays shared', async () => {
  const shared = row({ activity_type: 'practice', target_group_numbers: [1, 2] });
  const f = fixture([user(1), user(2), user(3)], { scenarios: {
    1: { state: { scheduleRows: [shared] } },
    2: { state: { scheduleRows: [{ ...shared, group_number: 2, selected_group: 2, target_group_numbers: [2, 1] }] } },
    3: { state: { scheduleRows: [{ ...shared, schedule_entry_id: 2, target_group_numbers: [3] }] } },
  } });
  const digest = await collectDailySchedule(f.deps, course, '2026-09-02');
  assert.deepEqual(digest.blocks.map((block) => block.students.length).sort(), [1, 2]);
  assert.match(buildDailyScheduleText(digest), /Групи 1, 2/);
});

test('no lessons, incomplete setup, unavailable data and outside semester stay distinct', async () => {
  const f = fixture([user(1), user(2), user(3), user(4), user(5), user(6)], { scenarios: {
    1: { state: { scheduleRows: [] } },
    2: { setup: { nextStep: 'subjects' } },
    3: { error: true },
    4: { state: { term: null } },
    5: { state: { term: { ...term, start_date: '2026-10-01' } } },
    6: { state: { scope: { group_id: 999 } } },
  } });
  const digest = await collectDailySchedule(f.deps, course, '2026-09-02');
  assert.equal(digest.blocks.find((b) => b.status === 'empty').students.length, 1);
  assert.equal(digest.blocks.find((b) => b.status === 'incomplete').students.length, 1);
  assert.equal(digest.blocks.find((b) => b.status === 'unavailable').students.length, 3);
  assert.equal(digest.blocks.find((b) => b.status === 'outside_term').students.length, 1);
  assert.equal(digest.blocks.at(-1).status, 'empty');
  const text = buildDailyScheduleText(digest);
  assert.doesNotMatch(text, /ще не налаштовано|student_2/);
});

test('header contains only the target weekday and date', async () => {
  const f = fixture();
  const text = buildDailyScheduleText(await collectDailySchedule(f.deps, course, '2026-09-02'));
  assert.ok(text.startsWith('<b>🌙 Розклад на середу</b>\n02.09.2026\n\n'));
  assert.doesNotMatch(text, /ПЛЕД|2025|Київ/);
});

test('weekends publish the chill message, while zero registered students have a different message', async () => {
  const f = fixture();
  const weekend = buildDailyScheduleText(await collectDailySchedule(f.deps, course, '2026-09-06'));
  assert.match(weekend, /Завтра чілім — пар немає/);
  const empty = fixture([]);
  const noStudents = buildDailyScheduleText(await collectDailySchedule(empty.deps, course, '2026-09-02'));
  assert.match(noStudents, /ще немає зареєстрованих студентів/);
  assert.doesNotMatch(noStudents, /чілім|пар немає/);
});

test('names use fallback and HTML escaping without clickable mentions', async () => {
  const f = fixture([user(1, { telegram_username: '@nickname' }), user(2, { telegram_username: '', full_name: '<Оля> & Іра' })]);
  const text = buildDailyScheduleText(await collectDailySchedule(f.deps, course, '2026-09-02'));
  assert.match(text, /<code>nickname<\/code>/);
  assert.match(text, /&lt;Оля&gt; &amp; Іра/);
  assert.doesNotMatch(text, /@|tg:\/\/|<a\b/);
});

test('long name lists compress before dropping any schedule block', async () => {
  const f = fixture(Array.from({ length: 70 }, (_, i) => user(i + 1, { telegram_username: `name${i}_${'x'.repeat(90)}` })));
  const text = buildDailyScheduleText(await collectDailySchedule(f.deps, course, '2026-09-02'));
  assert.ok(visibleLength(text) <= 3900);
  assert.match(text, /ще 67/);
  assert.match(text, /Англійська/);
  assert.doesNotMatch(text, /Не показано студентів/);
});

test('overflow removes whole blocks, preserves valid tags, and counts omitted students', async () => {
  const people = Array.from({ length: 60 }, (_, i) => user(i + 1));
  const scenarios = Object.fromEntries(people.map((person) => [person.id, { state: { scheduleRows: [
    row({ schedule_entry_id: person.id, subject_name: `<${'Довгий предмет & '.repeat(10)}>` }),
  ] } }]));
  const f = fixture(people, { scenarios });
  const text = buildDailyScheduleText(await collectDailySchedule(f.deps, course, '2026-09-02'));
  assert.ok(visibleLength(text) <= 3900);
  const omitted = Number(text.match(/Не показано студентів: (\d+)/)[1]);
  assert.equal((text.match(/<code>/g) || []).length + omitted, 60);
  const stack = [];
  for (const [, close, tag] of text.matchAll(/<(\/?)(b|code)>/g)) {
    if (close) assert.equal(stack.pop(), tag); else stack.push(tag);
  }
  assert.equal(stack.length, 0);
});

test('automatic job is due only at 18:00 and restart does not duplicate delivery', async () => {
  const f = fixture();
  const service = createDailyScheduleService(f.deps);
  f.current.date = new Date('2026-09-01T14:59:00Z');
  await service.tick();
  assert.equal(f.sent.length, 0);
  f.current.date = new Date('2026-09-01T15:00:00Z');
  await Promise.all([service.tick(), service.tick()]);
  await service.tick();
  await createDailyScheduleService(f.deps).tick();
  assert.equal(f.sent.length, 1);
  assert.equal(Array.from(f.records.values())[0].status, 'sent');
  assert.equal(f.sent[0].options.disableThreadFallback, true);
  assert.equal(f.sent[0].options.parseMode, 'HTML');
  assert.equal(f.sent[0].options.signal.aborted, false);
  f.current.date = new Date('2026-09-02T21:01:00Z'); // Kyiv midnight, no catchup for yesterday.
  await createDailyScheduleService(f.deps).tick();
  assert.equal(f.sent.length, 1);
  f.current.date = new Date('2026-09-03T15:00:00Z');
  await service.tick();
  assert.equal(f.sent.length, 2);
});

test('startup after the scheduled minute never catches up, but dev can still publish', async () => {
  const f = fixture();
  for (const timestamp of ['2026-09-01T15:01:00Z', '2026-09-01T19:00:00Z', '2026-09-01T20:59:00Z']) {
    f.current.date = new Date(timestamp);
    await createDailyScheduleService(f.deps).tick();
  }
  assert.equal(f.loads, 0);
  assert.equal(f.sent.length, 0);
  assert.equal(f.records.size, 0);
  await createDailyScheduleService(f.deps).handleCommand(command());
  assert.equal(f.sent.filter((message) => message.chatId === config().chatId).length, 1);
});

test('a slow lookup finishing after 18:00 cannot send a late automatic post', async () => {
  const f = fixture();
  f.deps.store.loadStudents = async () => { f.current.date = new Date('2026-09-01T15:01:00Z'); return [user(1)]; };
  await createDailyScheduleService(f.deps).tick();
  assert.equal(f.sent.length, 0);
  assert.equal(f.records.size, 0);
});

test('all-incomplete profiles stay hidden without an empty channel post', async () => {
  const f = fixture([user(1)], { scenarios: { 1: { setup: { nextStep: 'subjects' } } } });
  const digest = await collectDailySchedule(f.deps, course, '2026-09-02');
  assert.equal(buildDailyScheduleText(digest), null);
  const service = createDailyScheduleService(f.deps);
  await service.tick();
  assert.equal(f.sent.length, 0);
  await service.handleCommand(command(), 'preview');
  await service.handleCommand(command());
  assert.ok(f.sent.every((message) => message.chatId === 99 && !message.text.includes('student_1')));
  assert.equal(f.records.size, 0);
});

test('disabled and incomplete configurations never load or send', async () => {
  const f = fixture();
  for (const overrides of [{ enabled: false }, { chatId: '' }, { courseId: null, actorTelegramId: '' }, { invalid: true }]) {
    f.current.config = { ...config(), ...overrides };
    await createDailyScheduleService(f.deps).tick();
  }
  assert.equal(f.loads, 0);
  assert.equal(f.sent.length, 0);
});

test('a build crossing midnight cannot publish a stale tomorrow', async () => {
  const f = fixture();
  f.deps.store.loadStudents = async () => { f.current.date = new Date('2026-09-01T21:00:00Z'); return []; };
  await createDailyScheduleService(f.deps).tick();
  assert.equal(f.sent.length, 0);
});

for (const [label, telegramResponse, expected] of [
  ['bad topic', { ok: false, error_code: 400 }, 'failed'],
  ['missing channel permission', { ok: false, error_code: 403 }, 'failed'],
  ['rate limit', { ok: false, error_code: 429 }, 'failed'],
  ['server failure', { ok: false, error_code: 500 }, 'uncertain'],
  ['connection timeout', undefined, 'uncertain'],
]) {
  test(`${label} is recorded and never automatically resent after restart`, async () => {
    const f = fixture();
    let attempts = 0;
    f.deps.sendMessage = async () => { attempts += 1; throw Object.assign(new Error(label), { telegramResponse }); };
    await createDailyScheduleService(f.deps).tick();
    await createDailyScheduleService(f.deps).tick();
    assert.equal(attempts, 1);
    assert.equal(Array.from(f.records.values())[0].status, expected);
  });
}

test('a crash after the claim and a failed success journal write both prevent replay', async () => {
  const f = fixture();
  f.deps.store.finishDelivery = async () => { throw new Error('database unavailable'); };
  await createDailyScheduleService(f.deps).tick();
  assert.equal(Array.from(f.records.values())[0].status, 'sending');
  await createDailyScheduleService(f.deps).tick();
  assert.equal(f.sent.length, 1);
});

const command = (extra = {}) => ({ message_id: 101, from: { id: 99 }, chat: { id: 99, type: 'private' }, ...extra });

test('dev commands require an authenticated private dev; no data is loaded for other actors', async () => {
  const f = fixture();
  const service = createDailyScheduleService(f.deps);
  for (const message of [command({ from: { id: 5 } }), command({ chat: { id: -1002, type: 'supergroup' } }),
    command({ sender_chat: { id: 1 } }), command({ from: { id: 99, is_bot: true } })]) {
    await service.handleCommand(message);
  }
  assert.equal(f.loads, 0);
  assert.equal(f.records.size, 0);
  assert.ok(f.sent.every((message) => message.chatId !== config().chatId));
});

test('preview works while automatic delivery is disabled and matches the channel text', async () => {
  const f = fixture();
  f.current.config.enabled = false;
  const service = createDailyScheduleService(f.deps);
  await service.handleCommand(command(), 'preview');
  assert.equal(f.records.size, 0);
  assert.equal(f.sent[0].chatId, 99);
  await service.handleCommand(command());
  assert.equal(f.sent[1].chatId, config().chatId);
  assert.equal(f.sent[0].text, f.sent[1].text);
  assert.deepEqual(f.sent[0].options.replyMarkup, f.sent[1].options.replyMarkup);
});

test('manual commands do not suppress evening delivery and the same Telegram command is deduplicated', async () => {
  const f = fixture();
  const service = createDailyScheduleService(f.deps);
  await service.handleCommand(command());
  await service.handleCommand(command());
  await service.tick();
  assert.equal(f.sent.filter((message) => message.chatId === config().chatId).length, 2);
  assert.deepEqual(Array.from(f.records.values()).map((record) => record.mode).sort(), ['automatic', 'manual']);
});

test('private acknowledgement failure cannot trigger a second channel post', async () => {
  const f = fixture();
  const send = f.deps.sendMessage;
  f.deps.sendMessage = async (...args) => {
    if (args[0] === 99) throw new Error('private chat blocked');
    return send(...args);
  };
  const service = createDailyScheduleService(f.deps);
  await assert.rejects(service.handleCommand(command()), /blocked/);
  await assert.rejects(service.handleCommand(command()), /blocked/);
  assert.equal(f.sent.length, 1);
  assert.equal(Array.from(f.records.values())[0].status, 'sent');
});
