import { randomUUID } from "node:crypto";
import type { OrderStatus } from "@prisma/client";
import { prisma } from "../src/lib/prisma";
import { absoluteSiteUrl } from "../src/lib/site-url";
import { effectiveUnitPrice } from "../src/lib/pricing";
import { addInternalOrderComment, transitionOrderStatus } from "../src/lib/order-workflow";
import { reserveOrderInventory } from "../src/lib/inventory";
import { applyManualOrderText, buildManualOrderCreateData, chooseManualOrderKind, createManualOrderSession, selectManualCatalogItem, type ManualOrderSession } from "../src/lib/manual-order";
import { setReviewStatus } from "../src/lib/data";
import { authorizeTelegramActor } from "../src/lib/telegram-access";

type TgUser = { id: number; first_name?: string; username?: string };
type TgMessage = { message_id: number; chat: { id: number }; message_thread_id?: number; from?: TgUser; text?: string };
type TgCallback = { id: string; from: TgUser; data?: string; message?: TgMessage };
type TgUpdate = { update_id: number; message?: TgMessage; callback_query?: TgCallback };

const token = process.env.YKG_TELEGRAM_BOT_TOKEN?.trim();
const chatId = process.env.YKG_TELEGRAM_CHAT_ID?.trim();
const topicId = Number(process.env.YKG_TELEGRAM_TOPIC_ID || "") || undefined;
if (!token || !chatId) throw new Error("YKG Telegram bot requires token and chat ID.");

const apiBase = `https://api.telegram.org/bot${token}`;
const sessions = new Map<string, ManualOrderSession>();
const commentTargets = new Map<string, string>();

async function api<T>(method: string, body: Record<string, unknown>) {
  const response = await fetch(`${apiBase}/${method}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(30_000) });
  const payload = await response.json() as { ok: boolean; result?: T; description?: string };
  if (!response.ok || !payload.ok) throw new Error(payload.description || `Telegram ${method} failed`);
  return payload.result as T;
}

function send(text: string, reply_markup?: Record<string, unknown>) {
  return api<TgMessage>("sendMessage", { chat_id: chatId, message_thread_id: topicId, text, parse_mode: "HTML", disable_web_page_preview: true, reply_markup });
}

function sameScope(message?: TgMessage) {
  if (!message || String(message.chat.id) !== chatId) return false;
  return topicId === undefined || message.message_thread_id === topicId;
}

async function staffFor(user?: TgUser) {
  if (!user) return null;
  return authorizeTelegramActor(prisma, user.id);
}

function esc(value: string) { return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] || char); }
function money(value: number) { return `${new Intl.NumberFormat("uk-UA").format(value)} грн`; }
const stepPrompts: Record<string, string> = {
  name: "Імʼя та прізвище клієнта?", phone: "Номер телефону?", telegram: "Telegram клієнта або номер?", delivery: "Місто та відділення / адреса Нової пошти?",
  unique_description: "Опишіть унікальну позицію.", unique_price: "Вкажіть погоджену ціну цілим числом.",
};

async function sendOrderCard(publicId: string) {
  const order = await prisma.order.findUnique({ where: { publicId }, include: { items: true } });
  if (!order) return send("Замовлення не знайдено.");
  const items = order.items.map((item) => `• ${esc(item.productTitle)}${item.variantLabel ? ` — ${esc(item.variantLabel)}` : ""} × ${item.quantity}`).join("\n");
  return send(`<b>Замовлення ${publicId.slice(0, 8).toUpperCase()}</b>\n${items}\n\n<b>${money(order.total)}</b> · ${order.status}\n${esc(order.firstName)} ${esc(order.lastName)} · ${esc(order.phone)}\n<a href="${absoluteSiteUrl(`/order/${publicId}`)}">Сторінка статусу</a>`, {
    inline_keyboard: [
      [{ text: "Прийняти", callback_data: `order:status:${publicId}:accepted` }, { text: "Відправити", callback_data: `order:status:${publicId}:shipped` }],
      [{ text: "Виконати", callback_data: `order:status:${publicId}:completed` }, { text: "Скасувати", callback_data: `order:status:${publicId}:cancelled` }],
      [{ text: "Коментар", callback_data: `order:comment:${publicId}` }],
    ],
  });
}

async function listOrders() {
  const orders = await prisma.order.findMany({ where: { status: { in: ["new", "accepted", "shipped"] } }, orderBy: { createdAt: "desc" }, take: 12 });
  if (!orders.length) return send("Активних замовлень немає.");
  return send(`<b>Активні замовлення</b>\n\n${orders.map((order) => `• <code>${order.publicId.slice(0, 8).toUpperCase()}</code> · ${order.status} · ${money(order.total)}`).join("\n")}`, { inline_keyboard: orders.map((order) => [{ text: `${order.publicId.slice(0, 8).toUpperCase()} · ${order.status}`, callback_data: `order:view:${order.publicId}` }]) });
}

async function catalogButtons() {
  const products = await prisma.product.findMany({ where: { status: "published" }, include: { variants: true }, orderBy: [{ sortOrder: "asc" }, { id: "asc" }], take: 20 });
  const rows = products.flatMap((product) => product.variants.length
    ? product.variants.map((variant) => [{ text: `${product.title} · ${variant.label}`, callback_data: `manual:item:${product.id}:${variant.id}` }])
    : [[{ text: product.title, callback_data: `manual:item:${product.id}:0` }]]);
  return rows.length ? send("Оберіть підтверджену позицію:", { inline_keyboard: rows }) : send("Немає опублікованих позицій. Створіть унікальне ручне замовлення.");
}

async function confirmManual(userId: string, session: ManualOrderSession) {
  const selection = session.selection;
  if (!selection) return;
  const item = selection.kind === "catalog" ? `${selection.item.productTitle}${selection.item.variantLabel ? ` — ${selection.item.variantLabel}` : ""}` : selection.description;
  const price = selection.kind === "catalog" ? selection.item.unitPrice : selection.agreedPrice;
  await send(`<b>Підтвердити ручне замовлення?</b>\n${esc(session.customerName)} · ${esc(session.phone)}\n${esc(item)} · ${money(price)}\n${esc(session.deliveryText)}`, { inline_keyboard: [[{ text: "Створити", callback_data: "manual:confirm" }, { text: "Скасувати", callback_data: "manual:cancel" }]] });
  sessions.set(userId, session);
}

async function handleText(message: TgMessage, staff: NonNullable<Awaited<ReturnType<typeof staffFor>>>) {
  const text = message.text?.trim() || "";
  const userId = String(message.from!.id);
  if (text === "/orders" || text.startsWith("/orders@")) return listOrders();
  if (text === "/manual" || text.startsWith("/manual@")) { sessions.set(userId, createManualOrderSession()); return send(stepPrompts.name); }
  if (text === "/start" || text.startsWith("/start@")) return send("YKG Staff Bot\n/orders — активні замовлення\n/manual — ручне замовлення");
  const commentPublicId = commentTargets.get(userId);
  if (commentPublicId) { commentTargets.delete(userId); await addInternalOrderComment(commentPublicId, text.slice(0, 1000), { label: `telegram:${staff.displayName}`, staffUserId: staff.id }); return send("Коментар додано."); }
  const session = sessions.get(userId);
  if (!session) return;
  const result = applyManualOrderText(session, text);
  if (!result.ok) return send(`⚠️ ${esc(result.error)}`);
  sessions.set(userId, result.session);
  if (result.session.step === "kind") return send("Тип позиції:", { inline_keyboard: [[{ text: "З каталогу", callback_data: "manual:kind:catalog" }, { text: "Унікальна", callback_data: "manual:kind:unique" }]] });
  if (result.session.step === "confirm") return confirmManual(userId, result.session);
  return send(stepPrompts[result.session.step] || "Продовжуйте.");
}

async function handleCallback(query: TgCallback, staff: NonNullable<Awaited<ReturnType<typeof staffFor>>>) {
  const data = query.data || "";
  const userId = String(query.from.id);
  await api("answerCallbackQuery", { callback_query_id: query.id }).catch(() => undefined);
  const statusMatch = data.match(/^order:status:([0-9a-f-]{36}):(new|accepted|shipped|completed|cancelled)$/i);
  if (statusMatch) { await transitionOrderStatus(statusMatch[1], statusMatch[2] as OrderStatus, { label: `telegram:${staff.displayName}`, staffUserId: staff.id }); return sendOrderCard(statusMatch[1]); }
  const viewMatch = data.match(/^order:view:([0-9a-f-]{36})$/i);
  if (viewMatch) return sendOrderCard(viewMatch[1]);
  const commentMatch = data.match(/^order:comment:([0-9a-f-]{36})$/i);
  if (commentMatch) { commentTargets.set(userId, commentMatch[1]); return send("Надішліть службовий коментар одним повідомленням."); }
  const reviewMatch = data.match(/^review:(approve|reject):(\d+)$/);
  if (reviewMatch) { await setReviewStatus(Number(reviewMatch[2]), reviewMatch[1] === "approve" ? "approved" : "rejected"); return send("Статус відгуку оновлено."); }
  if (data === "manual:cancel") { sessions.delete(userId); return send("Ручне замовлення скасовано."); }
  if (data.startsWith("manual:kind:")) { const session = sessions.get(userId); if (!session) return; const next = chooseManualOrderKind(session, data.endsWith("catalog") ? "catalog" : "unique"); sessions.set(userId, next); return next.step === "catalog" ? catalogButtons() : send(stepPrompts.unique_description); }
  const itemMatch = data.match(/^manual:item:(\d+):(\d+)$/);
  if (itemMatch) {
    const session = sessions.get(userId); if (!session) return;
    const product = await prisma.product.findUnique({ where: { id: Number(itemMatch[1]) }, include: { variants: true } }); if (!product || product.status !== "published") return send("Позиція вже недоступна.");
    const variant = Number(itemMatch[2]) ? product.variants.find((item) => item.id === Number(itemMatch[2])) : null;
    const regular = variant?.price ?? product.basePrice; if (regular === null || (product.variants.length && !variant)) return send("Ціну позиції не підтверджено.");
    const unitPrice = effectiveUnitPrice(product, regular, !variant);
    const next = selectManualCatalogItem(session, { productId: product.id, productSlug: product.slug, productTitle: product.title, productUrl: absoluteSiteUrl(`/product/${product.slug}`), variantId: variant?.id ?? null, variantLabel: variant?.label ?? "", unitPrice, regularUnitPrice: regular });
    return confirmManual(userId, next);
  }
  if (data === "manual:confirm") {
    const session = sessions.get(userId); if (!session) return;
    const publicId = randomUUID();
    await prisma.$transaction(async (db) => { const order = await db.order.create({ data: buildManualOrderCreateData(session, publicId), include: { items: true } }); if (session.selection?.kind === "catalog") await reserveOrderInventory(db, order.id); await db.auditEvent.create({ data: { staffUserId: staff.id, actorLabel: staff.displayName, action: "order.manual_created", entityType: "order", entityId: publicId } }); });
    sessions.delete(userId); await send("Ручне замовлення створено."); return sendOrderCard(publicId);
  }
}

async function main() {
  let offset = 0;
  while (true) {
    try {
      const updates = await api<TgUpdate[]>("getUpdates", { offset, timeout: 25, allowed_updates: ["message", "callback_query"] });
      for (const update of updates) {
        offset = update.update_id + 1;
        const scope = update.message || update.callback_query?.message;
        if (!sameScope(scope)) continue;
        const actor = update.message?.from || update.callback_query?.from;
        const staff = await staffFor(actor);
        if (!staff) { if (update.callback_query) await api("answerCallbackQuery", { callback_query_id: update.callback_query.id, text: "Доступ заборонено", show_alert: true }).catch(() => undefined); continue; }
        if (update.message) await handleText(update.message, staff);
        if (update.callback_query) await handleCallback(update.callback_query, staff);
      }
    } catch (error) { console.error("[ykg-bot]", error); await new Promise((resolve) => setTimeout(resolve, 2500)); }
  }
}

void main();
