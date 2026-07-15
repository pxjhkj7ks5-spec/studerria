import { createConfiguredAdminStore } from "./serverAdminStore.mjs";

const token = process.env.SHIELDLINE_TELEGRAM_BOT_TOKEN || "";
const enabled = String(process.env.SHIELDLINE_ADMIN_BOT_ENABLED || "false").toLowerCase() === "true";
const adminIds = new Set(String(process.env.SHIELDLINE_ADMIN_TELEGRAM_IDS || "").split(/[\s,;]+/).map((value) => value.trim()).filter(Boolean));
const adminLabel = process.env.SHIELDLINE_ADMIN_LABEL || "owner";
const publicUrl = String(process.env.SHIELDLINE_PUBLIC_URL || "https://studerria.com/shieldline").replace(/\/+$/, "");
const store = await createConfiguredAdminStore();
let offset = 0;
let stopping = false;

function log(level, message, fields = {}) {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), level, service: "shieldline-admin-bot", message, ...fields }));
}

async function telegram(method, payload = {}) {
  if (!token) throw new Error("SHIELDLINE_TELEGRAM_BOT_TOKEN is not configured.");
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.ok) throw new Error(result.description || `Telegram ${method} failed.`);
  return result.result;
}

function keyboard(rows) {
  return { inline_keyboard: rows };
}

async function send(chatId, text, replyMarkup = undefined) {
  return telegram("sendMessage", { chat_id: chatId, text, parse_mode: "HTML", disable_web_page_preview: true, ...(replyMarkup ? { reply_markup: replyMarkup } : {}) });
}

function userText(user) {
  if (!user) return "Користувача не знайдено.";
  const telegramName = user.telegram?.username ? `@${user.telegram.username}` : user.telegram?.id || "—";
  return `<b>${escapeHtml(user.nickname || user.displayName || user.id)}</b>\n<code>${escapeHtml(user.id)}</code>\nСтатус: <b>${escapeHtml(user.status)}</b>\nTelegram: ${escapeHtml(telegramName)}\nПристрої: ${user.deviceCount} · Сесії: ${user.sessionCount} · Операції: ${user.operationCount}`;
}

function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

async function confirmation(adminId, action, payload, label, danger = false, step = 1) {
  const actionToken = await store.createTelegramAction(adminId, action, payload, step);
  return keyboard([[{ text: danger ? `⚠️ ${label}` : `Підтвердити: ${label}`, callback_data: `dev:${actionToken}` }, { text: "Скасувати", callback_data: "dev:cancel" }]]);
}

async function mutationPreview(chatId, adminId, command, targetQuery) {
  const user = await store.resolveUser(targetQuery);
  if (!user) return send(chatId, "Користувача не знайдено. Передайте nickname, actor ID, @username або Telegram ID.");
  const map = {
    devsuspend: ["suspend", "Заблокувати", true],
    devactivate: ["activate", "Відновити доступ", false],
    devrevoke: ["revoke", "Відкликати сесії та пристрої", true],
    devresetprogress: ["reset-progress", "Скинути прогрес", true],
    devunlinktelegram: ["unlink-telegram", "Відв’язати Telegram", true],
  };
  const [action, label, danger] = map[command];
  return send(chatId, `${userText(user)}\n\nДія: <b>${label}</b>`, await confirmation(adminId, action, { actorId: user.id, reason: `Telegram: ${label}` }, label, danger));
}

async function handleCommand(message) {
  const chatId = String(message.chat.id);
  const adminId = String(message.from?.id || "");
  if (message.chat.type !== "private" || !adminIds.has(adminId)) {
    if (message.chat.type === "private") await send(chatId, "Недостатньо прав для dev-команд ShieldLine.");
    return;
  }
  const [rawCommand, ...rest] = String(message.text || "").trim().split(/\s+/);
  const command = rawCommand.toLowerCase().split("@")[0];
  const query = rest.join(" ").trim();
  if (["/start", "/devhelp"].includes(command)) {
    await send(chatId, `<b>ShieldLine Dev Console</b>\n\n/devstats — зведення\n/devusers [пошук] — користувачі\n/devuser &lt;користувач&gt; — профіль\n/devhealth — стан системи\n/devsuspend &lt;користувач&gt;\n/devactivate &lt;користувач&gt;\n/devrevoke &lt;користувач&gt;\n/devresetprogress &lt;користувач&gt;\n/devunlinktelegram &lt;користувач&gt;\n/devdelete &lt;користувач&gt;\n/devbroadcast &lt;текст&gt;\n/admin — вебадмінка`);
    return;
  }
  if (command === "/admin") { await send(chatId, "Вебадмінка використовує окремий пароль.", keyboard([[{ text: "Відкрити ShieldLine Admin", url: `${publicUrl}/admin` }]])); return; }
  if (command === "/devstats") {
    const stats = await store.dashboard();
    await send(chatId, `<b>ShieldLine сьогодні</b>\nКористувачі: ${stats.users}\nАктивні 24 год: ${stats.active_users}\nНові за 7 днів: ${stats.new_users}\nTelegram: ${stats.telegram_users}\nОперації 24 год: ${stats.operations}\nЧерга: ${stats.pending_notifications}`);
    return;
  }
  if (command === "/devhealth") { const health = await store.systemHealth(); await send(chatId, `<b>ShieldLine Health</b>\nPostgreSQL: ${health.database}\nOutbox pending: ${health.outbox.pending}\nПеревірено: ${escapeHtml(health.checkedAt)}`); return; }
  if (command === "/devusers") {
    const result = await store.listUsers({ query, limit: 10 });
    await send(chatId, result.items.length ? result.items.map((user) => `${user.status === "active" ? "🟢" : "🟠"} <b>${escapeHtml(user.nickname || user.id)}</b> · <code>${escapeHtml(user.id)}</code>`).join("\n") : "Користувачів не знайдено.");
    return;
  }
  if (command === "/devuser") { await send(chatId, userText(await store.resolveUser(query))); return; }
  if (["/devsuspend", "/devactivate", "/devrevoke", "/devresetprogress", "/devunlinktelegram"].includes(command)) {
    if (!query) { await send(chatId, "Після команди вкажіть користувача."); return; }
    await mutationPreview(chatId, adminId, command.slice(1), query); return;
  }
  if (command === "/devdelete") {
    const user = await store.resolveUser(query);
    if (!user) { await send(chatId, "Користувача не знайдено."); return; }
    const anonymize = await store.createTelegramAction(adminId, "anonymize", { actorId: user.id, reason: "Telegram: анонімізація" });
    const full = await store.createTelegramAction(adminId, "delete-step-1", { actorId: user.id, reason: "Telegram: повне видалення", confirmation: user.id });
    await send(chatId, `${userText(user)}\n\nОберіть режим видалення.`, keyboard([[{ text: "Анонімізувати", callback_data: `dev:${anonymize}` }], [{ text: "⚠️ Повністю видалити", callback_data: `dev:${full}` }], [{ text: "Скасувати", callback_data: "dev:cancel" }]]));
    return;
  }
  if (command === "/devbroadcast") {
    if (!query) { await send(chatId, "Формат: /devbroadcast текст повідомлення"); return; }
    const preview = await store.previewBroadcast();
    await send(chatId, `<b>Попередній перегляд розсилки</b>\n\n${escapeHtml(query)}\n\nОтримувачів: <b>${preview.recipientCount}</b>`, await confirmation(adminId, "broadcast", { text: query, reason: "Telegram: адміністративна розсилка" }, "Поставити в чергу", true));
    return;
  }
  await send(chatId, "Невідома dev-команда. Використайте /devhelp.");
}

async function executeAction(adminId, action) {
  const actor = { source: "telegram", label: adminLabel, telegramId: adminId };
  const { actorId, reason } = action.payload || {};
  if (action.action === "suspend") return store.suspend(actor, actorId, reason);
  if (action.action === "activate") return store.activate(actor, actorId, reason);
  if (action.action === "revoke") { await store.revokeSessions(actor, actorId, reason); return store.revokeDevices(actor, actorId, reason); }
  if (action.action === "reset-progress") return store.resetProgress(actor, actorId, reason);
  if (action.action === "unlink-telegram") return store.unlinkTelegram(actor, actorId, reason);
  if (action.action === "anonymize") return store.anonymize(actor, actorId, reason);
  if (action.action === "broadcast") return store.queueBroadcast(actor, action.payload.text, reason);
  if (action.action === "delete") return store.deleteUser(actor, actorId, action.payload.confirmation, reason);
  throw new Error("Невідома дія підтвердження.");
}

async function handleCallback(callback) {
  const adminId = String(callback.from?.id || "");
  const chatId = String(callback.message?.chat?.id || adminId);
  if (!adminIds.has(adminId) || callback.message?.chat?.type !== "private") return telegram("answerCallbackQuery", { callback_query_id: callback.id, text: "Недостатньо прав.", show_alert: true });
  if (callback.data === "dev:cancel") { await telegram("answerCallbackQuery", { callback_query_id: callback.id, text: "Скасовано" }); await send(chatId, "Дію скасовано."); return; }
  const actionToken = String(callback.data || "").replace(/^dev:/, "");
  const action = await store.consumeTelegramAction(actionToken, adminId);
  if (!action) { await telegram("answerCallbackQuery", { callback_query_id: callback.id, text: "Підтвердження недійсне або прострочене.", show_alert: true }); return; }
  if (action.action === "delete-step-1") {
    const second = await store.createTelegramAction(adminId, "delete", action.payload, 2);
    await telegram("answerCallbackQuery", { callback_query_id: callback.id, text: "Потрібне фінальне підтвердження" });
    await send(chatId, `⚠️ <b>Незворотне видалення</b>\nУсі дані <code>${escapeHtml(action.payload.actorId)}</code> буде стерто.`, keyboard([[{ text: "Видалити назавжди", callback_data: `dev:${second}` }, { text: "Скасувати", callback_data: "dev:cancel" }]]));
    return;
  }
  try {
    const result = await executeAction(adminId, action);
    await telegram("answerCallbackQuery", { callback_query_id: callback.id, text: "Виконано" });
    await send(chatId, `<b>Дію виконано.</b>\n${escapeHtml(result?.nickname || result?.actorId || result?.id || action.action)}`);
  } catch (error) {
    await telegram("answerCallbackQuery", { callback_query_id: callback.id, text: "Помилка", show_alert: true });
    await send(chatId, `Не вдалося виконати дію: ${escapeHtml(error.message)}`);
  }
}

async function processUpdate(update) {
  if (!await store.beginBotUpdate(update.update_id)) return;
  try {
    if (update.message?.text) await handleCommand(update.message);
    else if (update.callback_query) await handleCallback(update.callback_query);
    await store.finishBotUpdate(update.update_id);
  } catch (error) {
    await store.finishBotUpdate(update.update_id, "failed");
    throw error;
  }
}

async function setup() {
  if (!enabled) { log("info", "admin bot is disabled"); return; }
  if (!token || !adminIds.size) throw new Error("Admin bot requires SHIELDLINE_TELEGRAM_BOT_TOKEN and SHIELDLINE_ADMIN_TELEGRAM_IDS.");
  const commands = [{ command: "devhelp", description: "Dev-команди ShieldLine" }, { command: "devstats", description: "Стан ShieldLine" }, { command: "devusers", description: "Користувачі" }, { command: "devhealth", description: "Стан сервісів" }, { command: "admin", description: "Вебадмінка" }];
  for (const id of adminIds) await telegram("setMyCommands", { commands, scope: { type: "chat", chat_id: Number(id) } });
  if (String(process.env.SHIELDLINE_ADMIN_BOT_DROP_PENDING_UPDATES || "true").toLowerCase() === "true") await telegram("deleteWebhook", { drop_pending_updates: true });
  log("info", "admin bot started", { admins: adminIds.size });
  await store.pool.query(`INSERT INTO shieldline_worker_heartbeats (role, status, details) VALUES ('admin-bot','ready',$1::jsonb)
    ON CONFLICT (role) DO UPDATE SET status = EXCLUDED.status, details = EXCLUDED.details, updated_at = now()`, [JSON.stringify({ admins: adminIds.size })]);
}

process.on("SIGTERM", () => { stopping = true; });
process.on("SIGINT", () => { stopping = true; });
await setup();
while (!stopping) {
  if (!enabled) { await new Promise((resolve) => setTimeout(resolve, 30_000)); continue; }
  try {
    const updates = await telegram("getUpdates", { offset, timeout: 25, allowed_updates: ["message", "callback_query"] });
    await store.pool.query("UPDATE shieldline_worker_heartbeats SET status = 'ready', updated_at = now() WHERE role = 'admin-bot'");
    for (const update of updates) { offset = Math.max(offset, Number(update.update_id) + 1); await processUpdate(update); }
  } catch (error) { log("error", "poll failed", { error: error.message }); await new Promise((resolve) => setTimeout(resolve, 2_000)); }
}
await store.pool.end();
