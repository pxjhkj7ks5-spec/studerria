const RESET_FLOW = 'subjects_reset_confirm';
const CONFIRM_TTL_MS = 5 * 60 * 1000;

function createStuderriaTelegramSubjectReset(deps) {
  let running = false;
  const now = deps.now || Date.now;
  const logError = (error) => deps.logger?.error('Studerria subject reset failed', error);
  const isPrivateActor = (message, actorId) => (
    String(message?.chat?.type || '') === 'private'
    && String(message?.chat?.id || '') === actorId
  );

  async function handleCommand(message = {}) {
    const actorId = String(message.from?.id || '');
    if (!actorId || message.from?.is_bot || message.sender_chat || !deps.isDevUser(message.from || {})) {
      await deps.sendMessage(message.chat?.id, 'Недостатньо прав. Команда доступна тільки dev.', { sourceMessage: message });
      return;
    }
    if (!isPrivateActor(message, actorId)) {
      await deps.sendMessage(message.chat?.id, 'Напиши /resetsubjects в особистому чаті з ботом.', { sourceMessage: message });
      return;
    }
    let summary;
    try {
      summary = await deps.getSummary();
    } catch (error) {
      logError(error);
      await deps.sendMessage(message.chat.id, 'Не вдалося перевірити вибір предметів. Нічого не скинуто.');
      return;
    }
    if (!summary.users) {
      await deps.sendMessage(message.chat.id, 'Збереженого вибору предметів немає. Нічого скидати.');
      return;
    }
    // Both buttons share a one-shot operation; cancel invalidates confirm too.
    const state = { actorId, chatId: String(message.chat.id), status: 'pending', expiresAt: now() + CONFIRM_TTL_MS };
    const button = (action, text) => ({
      text,
      callback_data: deps.actions.createActionToken({ flow: RESET_FLOW, action, state }),
    });
    await deps.sendMessage(message.chat.id, [
      'Скинути вибір предметів усім користувачам Studerria?',
      `Зараз: ${summary.users} користувачів, ${summary.selections} виборів груп і ${summary.optouts} позначок «не вивчаю».`,
      'Після підтвердження буде скинуто весь вибір, збережений на той момент, для всіх курсів.',
      'Оцінки, каталог, розклад, викладацькі призначення й участь у Teamwork не зміняться.',
      'Резервна копія вибору залишиться в журналі. Обов’язкові предмети з однією групою призначатимуться автоматично, як раніше.',
      'Підтвердження діє 5 хвилин.',
    ].join('\n\n'), {
      replyMarkup: { inline_keyboard: [[button('confirm', 'Скинути всім'), button('cancel', 'Скасувати')]] },
    });
  }

  async function handleCallback(callbackQuery = {}) {
    const payload = deps.actions.getActionPayload(callbackQuery.data);
    if (!payload || payload.flow !== RESET_FLOW) {
      await deps.answerCallback(callbackQuery, 'Підтвердження застаріло. Запусти /resetsubjects ще раз.');
      return;
    }
    const actorId = String(callbackQuery.from?.id || '');
    if (!actorId || callbackQuery.from?.is_bot || !deps.isDevUser(callbackQuery.from || {})) {
      await deps.answerCallback(callbackQuery, 'Недостатньо прав.', { showAlert: true });
      return;
    }
    const state = payload.state;
    if (!state || state.actorId !== actorId || state.chatId !== String(callbackQuery.message?.chat?.id || '')
      || !isPrivateActor(callbackQuery.message, actorId)) {
      await deps.answerCallback(callbackQuery, 'Це підтвердження відкрив інший користувач.', { showAlert: true });
      return;
    }
    if (state.status !== 'pending' || now() >= state.expiresAt) {
      await deps.answerCallback(callbackQuery, 'Підтвердження вже використане або застаріло.');
      return;
    }
    if (!['cancel', 'confirm'].includes(payload.action)) return;
    if (payload.action === 'confirm' && running) {
      await deps.answerCallback(callbackQuery, 'Інше скидання вже виконується.');
      return;
    }
    if (!deps.actions.consumeActionPayload(callbackQuery.data)) return;
    state.status = payload.action === 'cancel' ? 'cancelled' : 'running';
    if (payload.action === 'cancel') {
      await deps.answerCallback(callbackQuery, 'Скасовано.');
      await deps.editMessage(callbackQuery, 'Скидання скасовано. Вибір предметів збережено.').catch(logError);
      return;
    }
    running = true;
    await deps.answerCallback(callbackQuery, 'Скидаю вибір предметів…').catch(logError);
    let result;
    try {
      result = await deps.resetAll({ actorTelegramId: actorId });
      state.status = 'completed';
    } catch (error) {
      state.status = 'failed';
      logError(error);
      await deps.editMessage(callbackQuery, 'Не вдалося скинути вибір. Транзакцію скасовано, дані не змінено. Запусти /resetsubjects ще раз.').catch(logError);
      return;
    } finally {
      running = false;
    }
    // A notification failure must never turn a committed reset into a retry.
    try { await deps.onReset?.(result); } catch (error) { logError(error); }
    await deps.editMessage(callbackQuery, [
      `Вибір предметів скинуто для ${result.users} користувачів.`,
      `Прибрано виборів груп: ${result.selections}; позначок «не вивчаю»: ${result.optouts}.`,
      `Резервний запис у журналі: #${result.auditId}.`,
      'Користувачі можуть повторно обрати предмети в Studerria. Каталог, розклад і оцінки збережено.',
    ].join('\n')).catch(logError);
  }

  return { handleCommand, handleCallback };
}

module.exports = { RESET_FLOW, CONFIRM_TTL_MS, createStuderriaTelegramSubjectReset };
