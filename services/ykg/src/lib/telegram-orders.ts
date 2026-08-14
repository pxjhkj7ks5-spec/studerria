import type { DeliveryMethod, PaymentMethod } from "@prisma/client";
import { absoluteSiteUrl } from "@/lib/site-url";
import type { StockWarning } from "@/lib/inventory";

type NotificationOrder = {
  publicId: string;
  firstName: string;
  lastName: string;
  phone: string;
  telegramContact: string;
  comment: string;
  cityName: string;
  deliveryMethod: DeliveryMethod;
  deliveryDestination: string;
  courierAddress: string;
  paymentMethod: PaymentMethod;
  total: number;
  subtotal: number;
  saleDiscountAmount: number;
  discountAmount: number;
  promoCodeSnapshot: string;
  items: Array<{
    productTitle: string;
    variantLabel: string;
    quantity: number;
    unitPrice: number;
    totalPrice: number;
    productUrl: string;
  }>;
};

function escapeHtml(value: string) {
  return value.replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] || char,
  );
}

function formatAmount(value: number) {
  return `${new Intl.NumberFormat("uk-UA").format(value)} грн`;
}

const deliveryLabels: Record<DeliveryMethod, string> = {
  branch: "Відділення Нової пошти",
  parcel_locker: "Поштомат Нової пошти",
  courier: "Курʼєр Нової пошти",
};

const paymentLabels: Record<PaymentMethod, string> = {
  cash_on_delivery: "Післяплата",
  transfer: "Переказ після підтвердження",
};

export async function notifyOwnerAboutOrder(order: NotificationOrder, stockWarnings: StockWarning[] = []) {
  const token = process.env.YKG_TELEGRAM_BOT_TOKEN?.trim();
  const chatId = process.env.YKG_TELEGRAM_CHAT_ID?.trim();
  const topicId = Number(process.env.YKG_TELEGRAM_TOPIC_ID || "") || undefined;

  if (!token || !chatId) return { status: "skipped" as const, error: "", messageId: null };

  const itemLines = order.items.map((item, index) => {
    const variant = item.variantLabel ? ` — ${escapeHtml(item.variantLabel)}` : "";
    const productLink = item.productUrl
      ? `\n🔗 <a href="${escapeHtml(item.productUrl)}">Відкрити товар на сайті</a>`
      : "";
    return `${index + 1}. ${escapeHtml(item.productTitle)}${variant}${productLink}\n${item.quantity} × ${formatAmount(item.unitPrice)} = <b>${formatAmount(item.totalPrice)}</b>`;
  });
  const reviewUrl = `${absoluteSiteUrl("/reviews")}?order=${encodeURIComponent(order.publicId)}`;
  const itemChunks: string[] = [];
  for (const line of itemLines) {
    const current = itemChunks.at(-1) ?? "";
    if (current && current.length + line.length > 3200) itemChunks.push(line);
    else if (itemChunks.length === 0) itemChunks.push(line);
    else itemChunks[itemChunks.length - 1] = `${current}\n\n${line}`;
  }
  const sendItemsSeparately = itemChunks.length > 1;
  const destination = order.deliveryMethod === "courier" ? order.courierAddress : order.deliveryDestination;
  const text = [
    `<b>Нове замовлення ${escapeHtml(order.publicId.slice(0, 8).toUpperCase())}</b>`,
    "",
    ...(sendItemsSeparately ? [`<b>Позицій у замовленні:</b> ${order.items.length} (деталі надіслані вище)`] : itemLines),
    "",
    order.saleDiscountAmount ? `<b>Знижка на товари:</b> −${formatAmount(order.saleDiscountAmount)}` : "",
    order.discountAmount ? `<b>Промокод ${escapeHtml(order.promoCodeSnapshot)}:</b> −${formatAmount(order.discountAmount)}` : "",
    `<b>Разом:</b> ${formatAmount(order.total)}`,
    `<b>Статус:</b> Обробляється`,
    `<b>Покупець:</b> ${escapeHtml(order.firstName)} ${escapeHtml(order.lastName)}`,
    `<b>Телефон:</b> ${escapeHtml(order.phone)}`,
    `<b>Telegram:</b> ${escapeHtml(order.telegramContact)}`,
    `<b>Доставка:</b> ${deliveryLabels[order.deliveryMethod]}`,
    `<b>Місто:</b> ${escapeHtml(order.cityName)}`,
    `<b>Отримання:</b> ${escapeHtml(destination)}`,
    `<b>Оплата:</b> ${paymentLabels[order.paymentMethod]}`,
    order.comment ? `<b>Коментар:</b> ${escapeHtml(order.comment)}` : "",
    ...stockWarnings.map((warning) => `⚠️ <b>Склад:</b> ${escapeHtml(warning.productTitle)}${warning.variantLabel ? ` — ${escapeHtml(warning.variantLabel)}` : ""}: ${warning.balanceAfter}`),
  ].filter(Boolean).join("\n");

  try {
    async function send(payload: Record<string, unknown>) {
      const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(8000),
      });
      if (!response.ok) {
        const responseText = await response.text();
        throw new Error(`Telegram HTTP ${response.status}: ${responseText.slice(0, 240)}`);
      }
      const body = await response.json() as { result?: { message_id?: number } };
      return body.result?.message_id ?? null;
    }
    if (sendItemsSeparately) {
      for (const [index, chunk] of itemChunks.entries()) {
        await send({ chat_id: chatId, message_thread_id: topicId, text: `<b>Замовлення ${escapeHtml(order.publicId.slice(0, 8).toUpperCase())} · товари ${index + 1}/${itemChunks.length}</b>\n\n${chunk}`, parse_mode: "HTML", disable_web_page_preview: true });
      }
    }
    const messageId = await send({
        chat_id: chatId,
        message_thread_id: topicId,
        text,
        parse_mode: "HTML",
        disable_web_page_preview: true,
        reply_markup: { inline_keyboard: [
          [
            { text: "Відкрити замовлення", callback_data: `order:view:${order.publicId}` },
            { text: "Прийняти в роботу", callback_data: `order:status:${order.publicId}:accepted` },
          ],
          [
            { text: "Відправити", callback_data: `order:status:${order.publicId}:shipped` },
            { text: "Виконати", callback_data: `order:status:${order.publicId}:completed` },
          ],
          [
            { text: "Скасувати", callback_data: `order:status:${order.publicId}:cancelled` },
            { text: "Коментар", callback_data: `order:comment:${order.publicId}` },
          ],
          [{ text: "Відгук для покупця", url: reviewUrl }],
        ] },
      });
    return { status: "sent" as const, error: "", messageId };
  } catch (error) {
    return { status: "failed" as const, error: error instanceof Error ? error.message.slice(0, 500) : "Unknown Telegram error", messageId: null };
  }
}
