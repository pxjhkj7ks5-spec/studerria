import type { DeliveryMethod, PaymentMethod } from "@prisma/client";

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
  return value.replace(/[&<>]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[char] || char);
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

export async function notifyOwnerAboutOrder(order: NotificationOrder) {
  const token = process.env.NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN?.trim();
  const chatId = process.env.NARADADRUK_ORDER_TELEGRAM_CHAT_ID?.trim();
  const threadId = process.env.NARADADRUK_ORDER_TELEGRAM_THREAD_ID?.trim();

  if (!token || !chatId) return { status: "skipped" as const, error: "" };

  const itemLines = order.items.map((item, index) => {
    const variant = item.variantLabel ? ` — ${escapeHtml(item.variantLabel)}` : "";
    return `${index + 1}. <a href="${escapeHtml(item.productUrl)}">${escapeHtml(item.productTitle)}</a>${variant}\n${item.quantity} × ${formatAmount(item.unitPrice)} = <b>${formatAmount(item.totalPrice)}</b>`;
  });
  const destination = order.deliveryMethod === "courier" ? order.courierAddress : order.deliveryDestination;
  const text = [
    `<b>Нове замовлення ${escapeHtml(order.publicId.slice(0, 8).toUpperCase())}</b>`,
    "",
    ...itemLines,
    "",
    `<b>Разом:</b> ${formatAmount(order.total)}`,
    `<b>Покупець:</b> ${escapeHtml(order.firstName)} ${escapeHtml(order.lastName)}`,
    `<b>Телефон:</b> ${escapeHtml(order.phone)}`,
    `<b>Telegram:</b> ${escapeHtml(order.telegramContact)}`,
    `<b>Доставка:</b> ${deliveryLabels[order.deliveryMethod]}`,
    `<b>Місто:</b> ${escapeHtml(order.cityName)}`,
    `<b>Отримання:</b> ${escapeHtml(destination)}`,
    `<b>Оплата:</b> ${paymentLabels[order.paymentMethod]}`,
    order.comment ? `<b>Коментар:</b> ${escapeHtml(order.comment)}` : "",
  ].filter(Boolean).join("\n");

  try {
    const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        ...(threadId ? { message_thread_id: Number(threadId) } : {}),
        text,
        parse_mode: "HTML",
        disable_web_page_preview: true,
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok) {
      const responseText = await response.text();
      throw new Error(`Telegram HTTP ${response.status}: ${responseText.slice(0, 240)}`);
    }
    return { status: "sent" as const, error: "" };
  } catch (error) {
    return { status: "failed" as const, error: error instanceof Error ? error.message.slice(0, 500) : "Unknown Telegram error" };
  }
}

