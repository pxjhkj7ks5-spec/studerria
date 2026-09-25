const { getDayNameFromDate } = require('./dateUtils');

const DAY_MS = 86400000;
const MESSAGE_LIMIT = 3900;
const DAY_LABELS = ['неділю', 'понеділок', 'вівторок', 'середу', 'четвер', 'пʼятницю', 'суботу'];
const TYPE_LABELS = { lecture: 'Лекція', seminar: 'Семінар', practice: 'Практика', lab: 'Лаба' };
const DELIVERY_LABELS = { offline: 'Офлайн', online: 'Онлайн', mixed: 'Змішано' };
const positiveInt = (value) => Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Number(value) : null;
const clean = (value, max = 160) => Array.from(String(value || '').replace(/\s+/g, ' ').trim()).slice(0, max).join('');
const escapeHtml = (value) => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const compare = (a, b) => String(a).localeCompare(String(b), 'uk');
const studentName = (user) => clean(user.telegram_username || user.full_name || 'Студент', 120).replace(/@/g, '');

function studentMention(user) {
  const taggingEnabled = user.telegram_tag_enabled !== false;
  const label = escapeHtml(`${taggingEnabled && user.telegram_username ? '@' : ''}${studentName(user)}`);
  const telegramId = String(user.telegram_id || '').trim();
  return taggingEnabled && /^[1-9][0-9]*$/.test(telegramId)
    ? `<a href="tg://user?id=${telegramId}">${label}</a>`
    : label;
}

function getKyivClock(date = new Date()) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Kyiv', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).formatToParts(date);
  const part = (name) => parts.find((item) => item.type === name).value;
  return { dateIso: `${part('year')}-${part('month')}-${part('day')}`, hour: Number(part('hour')), minute: Number(part('minute')) };
}

function shiftDate(dateIso, days) {
  return new Date(Date.parse(`${dateIso}T00:00:00Z`) + days * DAY_MS).toISOString().slice(0, 10);
}

function parseTime(value) {
  const match = String(value || '18:00').trim().match(/^(\d{1,2}):(\d{2})$/);
  const valid = match && Number(match[1]) < 24 && Number(match[2]) < 60;
  const hour = valid ? Number(match[1]) : 18;
  const minute = valid ? Number(match[2]) : 0;
  return { hour, minute, label: `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}` };
}

function getDailyScheduleConfig(env = process.env) {
  const interval = Number(env.STUDERRIA_TG_DAILY_SCHEDULE_CHECK_INTERVAL_MS || 30000);
  const threadRaw = String(env.STUDERRIA_TG_DAILY_SCHEDULE_THREAD_ID || '').trim();
  const courseRaw = String(env.STUDERRIA_TG_DAILY_SCHEDULE_COURSE_ID || '').trim();
  return {
    enabled: ['1', 'true', 'yes', 'on'].includes(String(env.STUDERRIA_TG_DAILY_SCHEDULE_ENABLED || '').trim().toLowerCase()),
    chatId: String(env.STUDERRIA_TG_DAILY_SCHEDULE_CHAT_ID || '').trim(),
    courseId: positiveInt(courseRaw),
    actorTelegramId: String(env.STUDERRIA_TG_DAILY_SCHEDULE_ACTOR_TELEGRAM_ID || '').trim(),
    threadId: positiveInt(threadRaw),
    invalid: Boolean((threadRaw && !positiveInt(threadRaw)) || (courseRaw && !positiveInt(courseRaw))),
    time: parseTime(env.STUDERRIA_TG_DAILY_SCHEDULE_TIME),
    checkIntervalMs: Number.isFinite(interval) ? Math.max(10000, Math.min(60000, Math.floor(interval))) : 30000,
  };
}

function getTermWeek(term, targetIso) {
  const start = String(term?.start_date || '').slice(0, 10);
  const startMs = Date.parse(`${start}T00:00:00Z`);
  const weeks = positiveInt(term?.weeks_count);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(start) || !Number.isFinite(startMs)
    || new Date(startMs).toISOString().slice(0, 10) !== start || !weeks) return { status: 'unavailable' };
  const day = Math.floor((Date.parse(`${targetIso}T00:00:00Z`) - startMs) / DAY_MS);
  if (day < 0 || day >= weeks * 7) return { status: 'outside_term' };
  return { status: 'ready', weekNumber: Math.floor(day / 7) + 1 };
}

function normalizeLesson(row, formatTime, campus) {
  const type = row.activity_type || row.lesson_type || 'lecture';
  const groups = type === 'lecture' ? [] : Array.from(new Set(
    (row.target_group_numbers?.length ? row.target_group_numbers : [row.group_number])
      .map(positiveInt).filter(Boolean)
  )).sort((a, b) => a - b);
  const lesson = {
    classNumber: Number(row.class_number),
    subject: clean(row.subject_name || row.subject_title || 'Предмет'),
    type, groups,
    time: clean(formatTime(Number(row.class_number), campus), 40).replace(/-/g, '–'),
    room: clean(row.room_label || row.room_name || row.room_code, 60),
    deliveryMode: ['offline', 'online', 'mixed'].includes(String(row.delivery_mode || '').toLowerCase())
      ? String(row.delivery_mode).toLowerCase()
      : '',
  };
  // User-specific selected_group/group_label must not split a shared lecture or multi-group lesson.
  lesson.key = JSON.stringify([row.term_id, row.schedule_entry_id, row.group_subject_id,
    row.group_subject_activity_id, row.day_of_week, lesson.classNumber, type, groups, lesson.room, lesson.deliveryMode]);
  return lesson;
}

async function collectDailySchedule(deps, course, targetIso) {
  const students = await deps.store.loadStudents(course);
  const groups = new Map();
  const special = { incomplete: [], unavailable: [], outside_term: [], empty: [] };
  for (const user of students) {
    try {
      const setup = await deps.loadSetup(user);
      const base = setup?.subjectState;
      if (!base?.scope || Number(base.scope.group_id) !== Number(course.group_id)) {
        special.unavailable.push(user);
        continue;
      }
      if (!base.term || base.projectionIssues?.has_issues) {
        special.unavailable.push(user);
        continue;
      }
      if (setup.nextStep !== 'complete') {
        special.incomplete.push(user);
        continue;
      }
      const week = getTermWeek(base.term, targetIso);
      if (week.status !== 'ready') {
        special[week.status].push(user);
        continue;
      }
      const state = await deps.loadSchedule(user, week.weekNumber);
      if (!state?.term || Number(state.term.id) !== Number(base.term.id)
        || Number(state.scope?.group_id) !== Number(course.group_id) || state.projectionIssues?.has_issues) {
        special.unavailable.push(user);
        continue;
      }
      const showFullSchedule = Boolean(base.user && base.user.show_full_schedule);
      const selected = new Set((state.subjects || []).filter((subject) => subject.is_selected)
        .map((subject) => Number(subject.group_subject_id)));
      const lessons = Array.from(new Map((state.scheduleRows || [])
        .filter((row) => row.day_of_week === getDayNameFromDate(targetIso)
          && (showFullSchedule || selected.has(Number(row.group_subject_id))))
        .map((row) => normalizeLesson(row, deps.formatTime, base.scope.campus_key))
        .map((lesson) => [lesson.key, lesson])).values())
        .sort((a, b) => a.classNumber - b.classNumber || compare(a.subject, b.subject) || compare(a.key, b.key));
      if (!lessons.length) {
        special.empty.push(user);
        continue;
      }
      const key = JSON.stringify(lessons.map((lesson) => lesson.key));
      if (!groups.has(key)) groups.set(key, { students: [], lessons });
      groups.get(key).students.push(user);
    } catch (error) {
      deps.logger?.error('Studerria daily schedule student lookup failed', { userId: user.id, error: error.message });
      special.unavailable.push(user);
    }
  }
  const blocks = Array.from(groups.values()).sort((a, b) => a.lessons[0].classNumber - b.lessons[0].classNumber
    || compare(a.lessons.map((row) => row.subject).join('|'), b.lessons.map((row) => row.subject).join('|')));
  for (const [status, users] of Object.entries(special)) {
    if (users.length) blocks.push({ status, students: users, lessons: [] });
  }
  blocks.forEach((block) => block.students.sort((a, b) => compare(studentName(a), studentName(b)) || Number(a.id) - Number(b.id)));
  return { course, targetIso, blocks, studentCount: students.length };
}

function visibleLength(html) {
  return html.replace(/<[^>]*>/g, '').replace(/&(amp|lt|gt);/g, 'x').length;
}

function formatBlock(block, compact) {
  const shown = compact ? block.students.slice(0, 3) : block.students;
  const names = shown.map(studentMention).join(', ');
  const hidden = block.students.length - shown.length;
  const namesLine = `${names}${hidden ? `, ще ${hidden}` : ''}`;
  const labels = {
    unavailable: '⚠️ Розклад тимчасово недоступний',
    outside_term: '🗓 Завтра поза навчальним семестром',
  };
  if (block.status) return `<b>${labels[block.status]}</b>\n${namesLine}`;
  const lines = [`<b>👥 ${namesLine}</b>`, ''];
  for (const lesson of block.lessons) {
    lines.push(`• <b>${lesson.classNumber} пара</b>${lesson.time ? ` · ${escapeHtml(lesson.time)}` : ''} · <b>${escapeHtml(lesson.subject)}</b>`);
    const details = [TYPE_LABELS[lesson.type] || 'Пара',
      lesson.groups.length ? `${lesson.groups.length === 1 ? 'Група' : 'Групи'} ${lesson.groups.join(', ')}` : '',
      DELIVERY_LABELS[lesson.deliveryMode] || '',
      lesson.room].filter(Boolean).map(escapeHtml).join(' · ');
    lines.push(`   <i>${details}</i>`);
  }
  return lines.join('\n');
}

function buildDailyScheduleText(digest) {
  const date = new Date(`${digest.targetIso}T12:00:00Z`);
  const header = `<b>🌙 Розклад на ${DAY_LABELS[date.getUTCDay()]}</b>\n${digest.targetIso.split('-').reverse().join('.')}`;
  if (!digest.studentCount) return `${header}\n\nНа цьому курсі ще немає зареєстрованих студентів із прив’язаним Telegram.`;
  const visibleBlocks = digest.blocks.filter((block) => !['incomplete', 'empty'].includes(block.status));
  if (!visibleBlocks.length) {
    return digest.blocks.some((block) => block.status === 'empty')
      ? 'Завтра чіл'
      : null;
  }
  const render = (blocks, compact, omitted = 0) => {
    const shortened = compact && blocks.some((block) => block.students.length > 3);
    const footer = [omitted ? `Не показано студентів: ${omitted}.` : '',
      shortened || omitted ? 'Повний особистий розклад — за кнопкою «Мій розклад у Studeri».' : ''].filter(Boolean).join(' ');
    return [header, ...blocks.map((block) => formatBlock(block, compact)), footer].filter(Boolean).join('\n\n');
  };
  let text = render(visibleBlocks, false);
  if (visibleLength(text) <= MESSAGE_LIMIT) return text;
  const blocks = [...visibleBlocks];
  let omitted = 0;
  text = render(blocks, true);
  while (visibleLength(text) > MESSAGE_LIMIT && blocks.length) {
    omitted += blocks.pop().students.length;
    text = render(blocks, true, omitted);
  }
  return text;
}

function createDailyScheduleService(deps) {
  const now = deps.now || (() => new Date());
  const getConfig = deps.getConfig || getDailyScheduleConfig;
  let running = false;
  let automaticMinuteKey = '';
  const automaticBindingsHandled = new Set();
  const logError = (error) => deps.logger?.error('Studerria daily schedule failed', error);
  const configured = (config) => !config.invalid && config.chatId && (config.courseId || /^[1-9][0-9]*$/.test(config.actorTelegramId));
  const replyMarkup = () => deps.replyMarkup();

  const normalizeBinding = (row) => ({
    id: positiveInt(row?.id),
    groupId: positiveInt(row?.academic_group_id || row?.groupId),
    courseId: positiveInt(row?.course_id || row?.courseId),
    chatId: String(row?.chat_id || row?.chatId || '').trim(),
    threadId: positiveInt(row?.thread_id || row?.threadId),
    label: clean(row?.label || row?.program_name || `Привʼязка ${row?.id || ''}`, 90),
    programName: clean(row?.program_name, 90),
    admissionYear: positiveInt(row?.admission_year),
    campusKey: clean(row?.campus_key, 30),
  });

  async function loadActiveBindings(config = getConfig(), { allowLegacyDisabled = false } = {}) {
    await deps.ensureReady();
    if (typeof deps.store.importLegacyBinding === 'function') {
      await deps.store.importLegacyBinding(config);
    }
    if (typeof deps.store.listBindings === 'function') {
      return (await deps.store.listBindings({ activeOnly: true }))
        .map(normalizeBinding)
        .filter((binding) => binding.id && binding.groupId && binding.courseId && binding.chatId);
    }
    return (config.enabled || allowLegacyDisabled) && configured(config) ? [normalizeBinding(config)] : [];
  }

  async function prepare(binding, date) {
    if (!binding?.chatId || (!binding.groupId && !binding.courseId && !binding.actorTelegramId)) {
      throw new Error('Для привʼязки потрібні Telegram chat ID і активний академічний курс.');
    }
    await deps.ensureReady();
    const course = await deps.store.loadCourse(binding);
    const targetIso = shiftDate(getKyivClock(date).dateIso, 1);
    const digest = await collectDailySchedule(deps, course, targetIso);
    return { course, targetIso, text: buildDailyScheduleText(digest) };
  }

  async function deliver(binding, prepared, manualKey = null) {
    if (!prepared.text) return { status: 'no_schedule' };
    const mode = manualKey ? 'manual' : 'automatic';
    const key = JSON.stringify([mode, binding.id || 0, binding.chatId.toLowerCase(), binding.threadId || 0,
      prepared.course.course_id, prepared.targetIso, manualKey]);
    const claim = await deps.store.claimDelivery({ key, mode, targetIso: prepared.targetIso,
      chatId: binding.chatId, threadId: binding.threadId, courseId: prepared.course.course_id,
      bindingId: binding.id });
    if (!claim) return { status: 'duplicate' };
    let message;
    try {
      message = await deps.sendMessage(binding.chatId, prepared.text, {
        parseMode: 'HTML', replyMarkup: replyMarkup(), messageThreadId: binding.threadId,
        disableThreadFallback: true, signal: AbortSignal.timeout(30000),
      });
      if (!message?.message_id) throw new Error('Telegram did not return a message ID');
    } catch (error) {
      const response = error.telegramResponse;
      const status = response?.ok === false && Number(response.error_code) >= 400 && Number(response.error_code) < 500 ? 'failed' : 'uncertain';
      await deps.store.finishDelivery(claim.id, status, null, error.message).catch(logError);
      logError(error);
      return { status };
    }
    try {
      await deps.store.finishDelivery(claim.id, 'sent', message.message_id);
    } catch (error) {
      // Keep the durable 'sending' claim: a successful Telegram post must never be replayed.
      logError(error);
      return { status: 'sent', journalPending: true };
    }
    deps.logger?.log('Studerria daily schedule sent', { mode, targetIso: prepared.targetIso, messageId: message.message_id });
    return { status: 'sent' };
  }

  async function tick() {
    const config = getConfig();
    if (!deps.hasBotToken() || running) return;
    const date = now();
    const clock = getKyivClock(date);
    if (clock.hour !== config.time.hour || clock.minute !== config.time.minute) return;
    const minuteKey = `${clock.dateIso}:${config.time.label}`;
    if (automaticMinuteKey !== minuteKey) {
      automaticMinuteKey = minuteKey;
      automaticBindingsHandled.clear();
    }
    running = true;
    try {
      const bindings = await loadActiveBindings(config);
      await Promise.all(bindings.map(async (binding) => {
        if (automaticBindingsHandled.has(binding.id || binding.chatId)) return;
        try {
          const prepared = await prepare(binding, date);
          // Do not catch up after a restart or publish outside the scheduled minute after a slow lookup.
          const deliveryClock = getKyivClock(now());
          if (deliveryClock.dateIso !== clock.dateIso || deliveryClock.hour !== config.time.hour
            || deliveryClock.minute !== config.time.minute) return;
          await deliver(binding, prepared);
        } catch (error) {
          logError(error);
        } finally {
          automaticBindingsHandled.add(binding.id || binding.chatId);
        }
      }));
    } catch (error) {
      logError(error);
    } finally {
      running = false;
    }
  }

  async function handleCommand(message, args = '') {
    const actorId = String(message.from?.id || '');
    const chatId = message.chat?.id;
    if (!chatId) return;
    if (!actorId || message.from?.is_bot || message.sender_chat || !deps.isDevUser(message.from || {})) {
      await deps.sendMessage(chatId, 'Недостатньо прав. Команда доступна тільки dev.');
      return;
    }
    if (message.chat.type !== 'private' || String(chatId) !== actorId) {
      await deps.sendMessage(chatId, 'Напиши /devschedule в особистому чаті з ботом.');
      return;
    }
    if (!['', 'preview'].includes(args.trim())) {
      await deps.sendMessage(chatId, 'Формат: /devschedule або /devschedule preview');
      return;
    }
    try {
      const bindings = await loadActiveBindings(getConfig(), { allowLegacyDisabled: true });
      if (!bindings.length) {
        await deps.sendMessage(chatId, 'Немає активних привʼязок розсилки. Додай їх в адмінці Studerria.');
        return;
      }
      if (typeof deps.createActionToken !== 'function') {
        const binding = bindings[0];
        const prepared = await prepare(binding, now());
        if (!prepared.text) return deps.sendMessage(chatId, 'Немає готового розкладу для публікації.');
        if (args.trim() === 'preview') {
          await deps.sendMessage(chatId, prepared.text, { parseMode: 'HTML', replyMarkup: replyMarkup() });
          return;
        }
        const result = await deliver(binding, prepared, `${chatId}:${message.message_id}`);
        await sendResult(chatId, result);
        return;
      }
      const actorTelegramId = actorId;
      const rows = bindings.map((binding) => [{
        text: bindingButtonLabel(binding),
        callback_data: deps.createActionToken({ flow: 'daily_schedule', action: 'select',
          bindingId: binding.id, actorTelegramId, previewFirst: args.trim() === 'preview' }),
      }]);
      await deps.sendMessage(chatId, 'Обери привʼязку розсилки:', { replyMarkup: { inline_keyboard: rows } });
    } catch (error) {
      logError(error);
      await deps.sendMessage(chatId, `Не вдалося підготувати розсилку. ${clean(error.message, 240)}`);
    }
  }

  function bindingButtonLabel(binding) {
    const courseLabel = binding.label || [binding.programName, binding.admissionYear].filter(Boolean).join(' ') || `Курс ${binding.courseId}`;
    return clean(`${courseLabel} · ${binding.chatId}${binding.threadId ? `/${binding.threadId}` : ''}`, 60);
  }

  async function sendResult(chatId, result) {
    const replies = {
      sent: 'Розклад на завтра надіслано в налаштований канал. Вечірня розсилка залишається активною за конфігурацією.',
      duplicate: 'Цю команду вже оброблено. Повторно повідомлення не надсилаю.',
      failed: 'Telegram відхилив надсилання. Перевір канал, topic і право бота публікувати повідомлення.',
      uncertain: 'Не вдалося підтвердити доставку. Перевір канал перед повторною командою; автоматичного повтору не буде.',
      no_schedule: 'Немає готового розкладу для публікації.',
    };
    await deps.sendMessage(chatId, (replies[result.status] || 'Дію завершено.')
      + (result.journalPending ? ' Запис результату в журналі потребує перевірки.' : ''));
  }

  async function handleCallback(callbackQuery = {}, payload = {}) {
    if (String(payload.flow || '') !== 'daily_schedule') return false;
    const actorId = String(callbackQuery.from?.id || '');
    const chatId = callbackQuery.message?.chat?.id;
    if (!chatId || !actorId || callbackQuery.from?.is_bot || !deps.isDevUser(callbackQuery.from || {})
      || callbackQuery.message?.chat?.type !== 'private' || String(chatId) !== actorId
      || (payload.actorTelegramId && String(payload.actorTelegramId) !== actorId)) {
      await deps.answerCallback?.(callbackQuery, 'Недостатньо прав.');
      return true;
    }
    const binding = await deps.store.getBinding(payload.bindingId, { activeOnly: true });
    if (!binding) {
      await deps.answerCallback?.(callbackQuery, 'Привʼязка вже неактивна.');
      await deps.editMessage?.(callbackQuery, 'Привʼязка недоступна. Запусти /devschedule ще раз.');
      return true;
    }
    const normalized = normalizeBinding(binding);
    if (payload.action === 'select') {
      await deps.answerCallback?.(callbackQuery);
      const controls = { inline_keyboard: [[
        { text: 'Попередній перегляд', callback_data: deps.createActionToken({ flow: 'daily_schedule', action: 'preview', bindingId: normalized.id, actorTelegramId: actorId }) },
        { text: 'Надіслати', callback_data: deps.createActionToken({ flow: 'daily_schedule', action: 'send', bindingId: normalized.id, actorTelegramId: actorId }) },
      ]] };
      await deps.editMessage?.(callbackQuery, `Обрано: ${bindingButtonLabel(normalized)}\nРозсилка щодня о ${getConfig().time.label} за Києвом.`, controls);
      if (!payload.previewFirst) return true;
      try {
        const prepared = await prepare(normalized, now());
        await deps.sendMessage(chatId, prepared.text || 'Немає готового розкладу для публікації.',
          prepared.text ? { parseMode: 'HTML', replyMarkup: replyMarkup() } : {});
      } catch (error) {
        logError(error);
        await deps.sendMessage(chatId, `Не вдалося підготувати розсилку. ${clean(error.message, 240)}`);
      }
      return true;
    }
    if (payload.action === 'preview') {
      await deps.answerCallback?.(callbackQuery);
      try {
        const prepared = await prepare(normalized, now());
        await deps.sendMessage(chatId, prepared.text || 'Немає готового розкладу для публікації.',
          prepared.text ? { parseMode: 'HTML', replyMarkup: replyMarkup() } : {});
      } catch (error) {
        logError(error);
        await deps.sendMessage(chatId, `Не вдалося підготувати розсилку. ${clean(error.message, 240)}`);
      }
      return true;
    }
    if (payload.action === 'send') {
      const consumed = deps.consumeActionPayload?.(callbackQuery.data);
      if (!consumed) {
        await deps.answerCallback?.(callbackQuery, 'Цю дію вже оброблено.');
        return true;
      }
      await deps.answerCallback?.(callbackQuery, 'Надсилаю…');
      try {
        const date = now();
        const prepared = await prepare(normalized, date);
        if (getKyivClock(now()).dateIso !== getKyivClock(date).dateIso) throw new Error('Змінилася дата. Запусти команду ще раз.');
        const result = await deliver(normalized, prepared, `callback:${callbackQuery.id || callbackQuery.data}`);
        await sendResult(chatId, result);
      } catch (error) {
        logError(error);
        await deps.sendMessage(chatId, `Не вдалося підготувати розсилку. ${clean(error.message, 240)}`);
      }
      return true;
    }
    await deps.answerCallback?.(callbackQuery);
    return true;
  }

  return { tick, handleCommand, handleCallback, loadActiveBindings, prepare, deliver };
}

module.exports = { getDailyScheduleConfig, getKyivClock, shiftDate, getTermWeek,
  collectDailySchedule, buildDailyScheduleText, visibleLength, createDailyScheduleService };
