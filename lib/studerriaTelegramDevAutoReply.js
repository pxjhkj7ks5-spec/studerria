const MAX_REPLY_TEXT_LENGTH = 1000;

function normalizeTelegramId(value) {
  const normalized = String(value || '').trim();
  return /^\d+$/.test(normalized) && normalized !== '0' ? normalized : '';
}

function normalizeTelegramUsername(value) {
  return String(value || '')
    .trim()
    .replace(/^@/, '')
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, '')
    .slice(0, 32);
}

function parseStuderriaTelegramDevAutoReplyArgs(rawArgs = '') {
  const args = String(rawArgs || '').trim();
  if (!args) return { action: 'status' };
  const [rawAction = '', ...restParts] = args.split(/\s+/);
  const action = rawAction.toLowerCase();
  if (['on', 'off', 'status', 'clear'].includes(action)) {
    return restParts.length ? null : { action };
  }
  if (action !== 'set' || restParts.length < 2) return null;
  const target = restParts.shift();
  const replyText = restParts.join(' ').trim().slice(0, MAX_REPLY_TEXT_LENGTH);
  const targetTelegramId = normalizeTelegramId(target);
  const targetUsername = target.startsWith('@') ? normalizeTelegramUsername(target) : '';
  if ((!targetTelegramId && !targetUsername) || !replyText) return null;
  return {
    action: 'set',
    targetTelegramId,
    targetUsername,
    replyText,
  };
}

function isStuderriaTelegramGroupChat(chat = {}) {
  return ['group', 'supergroup'].includes(String(chat && chat.type || '').trim().toLowerCase());
}

function shouldSendStuderriaTelegramDevAutoReply(message = {}, rule = null) {
  if (!rule || rule.enabled !== true || !isStuderriaTelegramGroupChat(message.chat)) return false;
  if (!message.from || message.from.is_bot) return false;
  const senderId = normalizeTelegramId(message.from.id);
  const senderUsername = normalizeTelegramUsername(message.from.username);
  const targetId = normalizeTelegramId(rule.targetTelegramId || rule.target_telegram_id);
  const targetUsername = normalizeTelegramUsername(rule.targetUsername || rule.target_username);
  if (targetId) return senderId === targetId;
  return Boolean(targetUsername && senderUsername === targetUsername);
}

function normalizeRule(row = null) {
  if (!row) return null;
  return {
    enabled: row.enabled === true || ['1', 'true', 't', 'yes', 'on'].includes(String(row.enabled || '').toLowerCase()),
    targetTelegramId: normalizeTelegramId(row.target_telegram_id),
    targetUsername: normalizeTelegramUsername(row.target_username),
    replyText: String(row.reply_text || '').slice(0, MAX_REPLY_TEXT_LENGTH),
    updatedByTelegramId: normalizeTelegramId(row.updated_by_telegram_id),
    updatedAt: row.updated_at || null,
  };
}

function createStuderriaTelegramDevAutoReplyStore(db) {
  return {
    async getRule() {
      return normalizeRule(await db.get(`
        SELECT enabled, target_telegram_id, target_username, reply_text,
               updated_by_telegram_id, updated_at
        FROM studerria_telegram_dev_auto_reply
        WHERE id = 1
      `));
    },

    async setRule(rule = {}, actorTelegramId = '') {
      const targetTelegramId = normalizeTelegramId(rule.targetTelegramId);
      const targetUsername = normalizeTelegramUsername(rule.targetUsername);
      const replyText = String(rule.replyText || '').trim().slice(0, MAX_REPLY_TEXT_LENGTH);
      if ((!targetTelegramId && !targetUsername) || !replyText) throw new Error('invalid_auto_reply_rule');
      await db.run(`
        INSERT INTO studerria_telegram_dev_auto_reply
          (id, enabled, target_telegram_id, target_username, reply_text, updated_by_telegram_id, updated_at)
        VALUES (1, true, ?, ?, ?, ?, NOW())
        ON CONFLICT (id) DO UPDATE SET
          enabled = true,
          target_telegram_id = EXCLUDED.target_telegram_id,
          target_username = EXCLUDED.target_username,
          reply_text = EXCLUDED.reply_text,
          updated_by_telegram_id = EXCLUDED.updated_by_telegram_id,
          updated_at = NOW()
      `, [targetTelegramId || null, targetUsername || null, replyText, normalizeTelegramId(actorTelegramId) || null]);
      return this.getRule();
    },

    async setEnabled(enabled, actorTelegramId = '') {
      await db.run(`
        UPDATE studerria_telegram_dev_auto_reply
        SET enabled = ?, updated_by_telegram_id = ?, updated_at = NOW()
        WHERE id = 1
      `, [Boolean(enabled), normalizeTelegramId(actorTelegramId) || null]);
      return this.getRule();
    },

    async clear() {
      await db.run('DELETE FROM studerria_telegram_dev_auto_reply WHERE id = 1');
    },
  };
}

module.exports = {
  MAX_REPLY_TEXT_LENGTH,
  createStuderriaTelegramDevAutoReplyStore,
  isStuderriaTelegramGroupChat,
  normalizeTelegramId,
  normalizeTelegramUsername,
  parseStuderriaTelegramDevAutoReplyArgs,
  shouldSendStuderriaTelegramDevAutoReply,
};
