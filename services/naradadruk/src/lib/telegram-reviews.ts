import { NotificationStatus, type Review, type ReviewImage } from "@prisma/client";
import { readUploadFile, contentTypeForUpload } from "@/lib/storage";

type ReviewWithImages = Review & {
  images: ReviewImage[];
  order: { publicId: string } | null;
};
type TelegramResponse<T> = { ok?: boolean; result?: T; description?: string };

function escapeHtml(value: string) {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function telegramJson<T>(token: string, method: string, payload: Record<string, unknown>) {
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(20_000),
  });
  const result = await response.json().catch(() => ({})) as TelegramResponse<T>;
  if (!response.ok || !result.ok) {
    throw new Error(result.description || `Telegram HTTP ${response.status}`);
  }
  return result.result as T;
}

async function sendReviewPhotos(token: string, chatId: string, review: ReviewWithImages) {
  if (review.images.length === 0) return;
  const form = new FormData();
  form.set("chat_id", chatId);

  if (review.images.length === 1) {
    const image = review.images[0];
    const file = await readUploadFile(image.fileName);
    form.set("photo", new Blob([new Uint8Array(file)], { type: contentTypeForUpload(image.fileName) }), image.fileName);
    await telegramMultipart(token, "sendPhoto", form);
    return;
  }

  const media = [];
  for (const [index, image] of review.images.entries()) {
    const field = `review${index}`;
    const file = await readUploadFile(image.fileName);
    form.append(field, new Blob([new Uint8Array(file)], { type: contentTypeForUpload(image.fileName) }), image.fileName);
    media.push({ type: "photo", media: `attach://${field}` });
  }
  form.set("media", JSON.stringify(media));
  await telegramMultipart(token, "sendMediaGroup", form);
}

async function telegramMultipart(token: string, method: string, form: FormData) {
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    body: form,
    signal: AbortSignal.timeout(45_000),
  });
  const result = await response.json().catch(() => ({})) as TelegramResponse<unknown>;
  if (!response.ok || !result.ok) {
    throw new Error(result.description || `Telegram HTTP ${response.status}`);
  }
}

export async function notifyOwnerAboutReview(review: ReviewWithImages) {
  const token = process.env.NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN?.trim();
  const chatId = process.env.NARADADRUK_ORDER_TELEGRAM_CHAT_ID?.trim();
  if (!token || !chatId) {
    return { status: NotificationStatus.skipped, error: "Telegram review notification is not configured.", messageId: null };
  }

  try {
    await sendReviewPhotos(token, chatId, review);
    const name = review.isAnonymous || !review.displayName ? "Анонімно" : review.displayName;
    const text = [
      "🗣 <b>Новий опублікований відгук</b>",
      `Автор: <b>${escapeHtml(name)}</b>`,
      review.verifiedPurchase && review.order
        ? `✅ Підтверджене замовлення <b>#${escapeHtml(review.order.publicId.slice(0, 8).toUpperCase())}</b>`
        : "Без привʼязки до замовлення",
      `Фото: ${review.images.length}`,
      "",
      escapeHtml(review.body.slice(0, 3000)),
      "",
      "Відгук уже видно на сайті. Підтвердження не змінить його стан, а відхилення одразу приховає відгук.",
    ].join("\n");
    const message = await telegramJson<{ message_id: number }>(token, "sendMessage", {
      chat_id: chatId,
      text,
      parse_mode: "HTML",
      disable_web_page_preview: true,
      reply_markup: {
        inline_keyboard: [[
          { text: "Підтвердити", callback_data: `review:approve:${review.id}` },
          { text: "Відхилити", callback_data: `review:reject:${review.id}` },
        ]],
      },
    });
    return { status: NotificationStatus.sent, error: "", messageId: message.message_id };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown Telegram error";
    return { status: NotificationStatus.failed, error: message.slice(0, 500), messageId: null };
  }
}
