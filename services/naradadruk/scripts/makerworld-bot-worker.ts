import { access, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { PrismaClient, ProductStatus, ReviewStatus } from "@prisma/client";
import {
  fetchMakerWorldModel,
  isAllowedMakerWorldImageUrl,
  MakerWorldFetchError,
  parseMakerWorldUrl,
  type MakerWorldModel,
} from "../src/lib/makerworld";

type TelegramUser = { id: number };
type TelegramChat = { id: number; type: string };
type TelegramPhotoSize = { file_id: string; file_size?: number; width: number; height: number };
type TelegramFile = { file_id: string; file_size?: number; file_path?: string };
type TelegramMessage = {
  message_id: number;
  chat: TelegramChat;
  from?: TelegramUser;
  text?: string;
  caption?: string;
  photo?: TelegramPhotoSize[];
};
type TelegramCallbackQuery = {
  id: string;
  from: TelegramUser;
  data?: string;
  message?: TelegramMessage;
};
type TelegramUpdate = {
  update_id: number;
  message?: TelegramMessage;
  callback_query?: TelegramCallbackQuery;
};
type TelegramResponse<T> = { ok: boolean; result?: T; description?: string };

type DraftImage = {
  id: number;
  fileName: string;
  urlPath: string;
  sourceIndex: number;
  selected: boolean;
};

type AwaitingField = "url" | "title" | "description" | "summary" | "images" | "price" | null;

type DraftSession = {
  chatId: string;
  draftProductId: number;
  existingProductId: number | null;
  publishedProductId: number | null;
  publishedSlug: string | null;
  sourceUrl: string;
  title: string;
  siteDescription: string;
  telegramSummary: string;
  metadata: string[];
  author: string;
  price: number | null;
  images: DraftImage[];
  awaiting: AwaitingField;
  manualSetup: "title" | "description" | null;
  postSent: boolean;
};

type DownloadedImage = {
  fileName: string;
  urlPath: string;
  sourceIndex: number;
};

const prisma = new PrismaClient();
const sessions = new Map<string, DraftSession>();
type ManualOrderSession = { step: "contact" | "items" | "amount" | "delivery" | "payment" | "confirm"; name: string; contact: string; items: string; amount: number; delivery: string; payment: "cash_on_delivery" | "transfer" };
const manualOrders = new Map<string, ManualOrderSession>();
const awaitingOrderComments = new Map<string, string>();
let dashboardMessageId: number | null = null;
const botToken = process.env.NARADADRUK_ORDER_TELEGRAM_BOT_TOKEN?.trim() || "";
const ownerChatId = process.env.NARADADRUK_ORDER_TELEGRAM_CHAT_ID?.trim() || "";
const configuredOwnerUserIds = (process.env.NARADADRUK_ORDER_TELEGRAM_OWNER_USER_IDS || "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const hasInvalidOwnerUserId = configuredOwnerUserIds.some((value) => !/^[1-9]\d*$/.test(value));
const ownerUserIds = new Set(configuredOwnerUserIds.filter((value) => /^[1-9]\d*$/.test(value)));
if (ownerUserIds.size === 0 && /^[1-9]\d*$/.test(ownerChatId)) ownerUserIds.add(ownerChatId);
const postsChatId = process.env.NARADADRUK_POSTS_TELEGRAM_CHAT_ID?.trim() || "";
const publicSiteBaseUrl = new URL("https://studerria.com/naradadruk/");
const maxImages = 6;
const maxImageAttempts = 12;
const maxImageBytes = 8 * 1024 * 1024;
const maxTotalImageBytes = 24 * 1024 * 1024;
const userAgent =
  "Mozilla/5.0 (compatible; NaradaDrukMakerWorldBot/1.0; +https://t.me/naradaprint)";

function escapeHtml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function cleanText(value: string, maximumLength: number) {
  return value
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim()
    .slice(0, maximumLength);
}

function shortText(value: string, maximumLength: number) {
  const normalized = cleanText(value, maximumLength + 1);
  return normalized.length <= maximumLength
    ? normalized
    : `${normalized.slice(0, maximumLength - 1).trimEnd()}…`;
}

function slugify(value: string) {
  const normalized = value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLocaleLowerCase("uk-UA")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
  return normalized || `makerworld-${Date.now()}`;
}

function uploadDirectory() {
  const configured = process.env.UPLOAD_DIR || "./uploads";
  return path.isAbsolute(configured) ? configured : path.resolve(process.cwd(), configured);
}

function publicProductUrl(slug: string) {
  return new URL(`product/${encodeURIComponent(slug)}`, publicSiteBaseUrl).toString();
}

function normalizeTelegramLink(value: string) {
  const trimmed = value.trim();
  const webMatch = trimmed.match(/web\.telegram\.org\/[^#]*#@?([a-zA-Z0-9_]+)/i);
  if (webMatch) return `https://t.me/${webMatch[1]}`;

  try {
    const url = new URL(trimmed);
    const hostname = url.hostname.toLowerCase();
    if (url.protocol !== "https:" || !["t.me", "telegram.me", "www.telegram.me"].includes(hostname)) {
      return "";
    }
    return url.toString();
  } catch {
    return "";
  }
}

async function contactAndChannelLinks() {
  const settings = await prisma.siteSetting.findUnique({ where: { id: 1 } });
  const username = (process.env.TELEGRAM_CHANNEL_USERNAME || "naradaprint").replace(/^@/, "").trim();
  const channelLink =
    normalizeTelegramLink(process.env.TELEGRAM_CHANNEL_URL || "") ||
    (/^[a-zA-Z0-9_]{5,32}$/.test(username) ? `https://t.me/${username}` : "");
  const contactLink =
    normalizeTelegramLink(settings?.telegramUrl || "") ||
    channelLink;
  return { contactLink, channelLink };
}

async function telegramJson<T>(method: string, payload: Record<string, unknown>) {
  const response = await fetch(`https://api.telegram.org/bot${botToken}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(method === "getUpdates" ? 35_000 : 20_000),
  });
  const result = (await response.json().catch(() => ({}))) as TelegramResponse<T>;
  if (!response.ok || !result.ok) {
    throw new Error(`Telegram ${method}: ${cleanText(result.description || `HTTP ${response.status}`, 300)}`);
  }
  return result.result as T;
}

function editorKeyboard() {
  return {
    inline_keyboard: [
      [
        { text: "✏️ Назва", callback_data: "mw:title" },
        { text: "📝 Опис сайту", callback_data: "mw:description" },
      ],
      [
        { text: "📣 Текст Telegram", callback_data: "mw:summary" },
        { text: "🖼 Фото", callback_data: "mw:images" },
      ],
      [
        { text: "💰 Ціна", callback_data: "mw:price" },
        { text: "👁 Оновити превʼю", callback_data: "mw:preview" },
      ],
      [
        { text: "✅ Опублікувати", callback_data: "mw:publish" },
        { text: "✖️ Скасувати", callback_data: "mw:cancel" },
      ],
    ],
  };
}

async function sendMessage(chatId: string, text: string, replyMarkup?: Record<string, unknown>) {
  return telegramJson<TelegramMessage>("sendMessage", {
    chat_id: chatId,
    text,
    parse_mode: "HTML",
    disable_web_page_preview: true,
    ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
  });
}

async function answerCallback(id: string, text?: string) {
  await telegramJson("answerCallbackQuery", {
    callback_query_id: id,
    ...(text ? { text: shortText(text, 180) } : {}),
  }).catch(() => undefined);
}

async function telegramMultipart(method: string, form: FormData) {
  const response = await fetch(`https://api.telegram.org/bot${botToken}/${method}`, {
    method: "POST",
    body: form,
    signal: AbortSignal.timeout(45_000),
  });
  const result = (await response.json().catch(() => ({}))) as TelegramResponse<unknown>;
  if (!response.ok || !result.ok) {
    throw new Error(`Telegram ${method}: ${cleanText(result.description || `HTTP ${response.status}`, 300)}`);
  }
}

function mimeTypeForFile(fileName: string) {
  const extension = path.extname(fileName).toLowerCase();
  if (extension === ".png") return "image/png";
  if (extension === ".webp") return "image/webp";
  if (extension === ".avif") return "image/avif";
  return "image/jpeg";
}

async function sendPhotoSet(
  chatId: string,
  images: DraftImage[],
  title: string,
) {
  if (images.length === 0) return;
  const form = new FormData();
  form.set("chat_id", chatId);

  if (images.length === 1) {
    const image = images[0];
    const buffer = await readFile(path.join(uploadDirectory(), image.fileName));
    form.set("photo", new Blob([new Uint8Array(buffer)], { type: mimeTypeForFile(image.fileName) }), image.fileName);
    form.set("caption", `✦ ${shortText(title, 900)}`);
    await telegramMultipart("sendPhoto", form);
    return;
  }

  const media = [];
  for (const [index, image] of images.entries()) {
    const fieldName = `photo${index}`;
    const buffer = await readFile(path.join(uploadDirectory(), image.fileName));
    form.append(fieldName, new Blob([new Uint8Array(buffer)], { type: mimeTypeForFile(image.fileName) }), image.fileName);
    media.push({
      type: "photo",
      media: `attach://${fieldName}`,
      ...(index === 0 ? { caption: `✦ ${shortText(title, 900)}` } : {}),
    });
  }
  form.set("media", JSON.stringify(media));
  await telegramMultipart("sendMediaGroup", form);
}

async function readBinaryWithLimit(response: Response, maximumBytes: number) {
  const declared = Number(response.headers.get("content-length") || "0");
  if (declared > maximumBytes) throw new Error("Файл перевищує 8 MB.");
  if (!response.body) throw new Error("Порожня відповідь зображення.");

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel();
      throw new Error("Файл перевищує 8 MB.");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));
}

async function fetchImage(initialUrl: string) {
  let currentUrl = initialUrl;
  for (let redirect = 0; redirect <= 3; redirect += 1) {
    if (!isAllowedMakerWorldImageUrl(currentUrl)) throw new Error("Непідтримуваний CDN зображення.");
    const response = await fetch(currentUrl, {
      redirect: "manual",
      headers: { accept: "image/avif,image/webp,image/png,image/jpeg", "user-agent": userAgent },
      signal: AbortSignal.timeout(25_000),
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location || redirect === 3) throw new Error("Забагато перенаправлень зображення.");
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const contentType = (response.headers.get("content-type") || "").split(";")[0].toLowerCase();
    if (!["image/jpeg", "image/png", "image/webp", "image/avif"].includes(contentType)) {
      throw new Error("Непідтримуваний формат зображення.");
    }
    return { buffer: await readBinaryWithLimit(response, maxImageBytes), contentType };
  }
  throw new Error("Не вдалося завантажити зображення.");
}

async function downloadTelegramPhoto(photo: TelegramPhotoSize) {
  if (photo.file_size && photo.file_size > maxImageBytes) {
    throw new Error("Фото перевищує дозволені 8 MB.");
  }
  const file = await telegramJson<TelegramFile>("getFile", { file_id: photo.file_id });
  const filePath = file.file_path || "";
  if (
    !/^photos\/[a-zA-Z0-9_./-]+$/.test(filePath) ||
    filePath.includes("..") ||
    (file.file_size && file.file_size > maxImageBytes)
  ) {
    throw new Error("Telegram повернув непідтримуваний файл фото.");
  }

  const response = await fetch(`https://api.telegram.org/file/bot${botToken}/${filePath}`, {
    signal: AbortSignal.timeout(25_000),
  });
  if (!response.ok) throw new Error(`Telegram не віддав фото (HTTP ${response.status}).`);
  const buffer = await readBinaryWithLimit(response, maxImageBytes);
  if (buffer.length < 3 || buffer[0] !== 0xff || buffer[1] !== 0xd8 || buffer[2] !== 0xff) {
    throw new Error("Telegram-фото має непідтримуваний формат.");
  }
  return buffer;
}

async function addTelegramPhotoToDraft(session: DraftSession, photo: TelegramPhotoSize) {
  if (session.draftProductId <= 0) throw new Error("Спочатку завершіть назву й опис чернетки.");
  if (session.images.length >= maxImages) throw new Error(`До чернетки можна додати не більше ${maxImages} фото.`);
  const draft = await prisma.product.findFirst({
    where: { id: session.draftProductId, status: ProductStatus.draft },
    select: { id: true },
  });
  if (!draft) throw new Error("Неопубліковану чернетку більше не знайдено.");

  const buffer = await downloadTelegramPhoto(photo);
  await mkdir(uploadDirectory(), { recursive: true });
  const fileName = `telegram-${session.draftProductId}-${session.images.length + 1}-${Date.now()}.jpg`;
  await writeFile(path.join(uploadDirectory(), fileName), buffer);
  try {
    const image = await prisma.productImage.create({
      data: {
        productId: session.draftProductId,
        fileName,
        urlPath: `/uploads/${fileName}`,
        alt: `${session.title} — фото товару`,
        sortOrder: (session.images.length + 1) * 10,
        isCover: session.images.length === 0,
      },
    });
    session.images.push({
      id: image.id,
      fileName: image.fileName,
      urlPath: image.urlPath,
      sourceIndex: session.images.length + 1,
      selected: true,
    });
    console.info(`[makerworld-bot] Telegram photo persisted: draft=${session.draftProductId} image=${image.id} file=${fileName}`);
  } catch (error) {
    await unlink(path.join(uploadDirectory(), fileName)).catch(() => undefined);
    throw error;
  }
}

function extensionForContentType(contentType: string) {
  if (contentType === "image/png") return "png";
  if (contentType === "image/webp") return "webp";
  if (contentType === "image/avif") return "avif";
  return "jpg";
}

async function downloadModelImages(model: MakerWorldModel) {
  const result: DownloadedImage[] = [];
  let totalBytes = 0;
  await mkdir(uploadDirectory(), { recursive: true });

  for (const [sourceIndex, imageUrl] of model.imageUrls.slice(0, maxImageAttempts).entries()) {
    if (result.length >= maxImages || totalBytes >= maxTotalImageBytes) break;
    try {
      const image = await fetchImage(imageUrl);
      if (totalBytes + image.buffer.byteLength > maxTotalImageBytes) break;
      const fileName = `${slugify(model.title)}-makerworld-${sourceIndex + 1}-${Date.now()}.${extensionForContentType(image.contentType)}`;
      await writeFile(path.join(uploadDirectory(), fileName), image.buffer);
      totalBytes += image.buffer.byteLength;
      result.push({ fileName, urlPath: `/uploads/${fileName}`, sourceIndex: sourceIndex + 1 });
    } catch (error) {
      const message = error instanceof Error ? error.message : "невідома помилка";
      console.warn(`[makerworld-bot] image ${sourceIndex + 1} skipped: ${shortText(message, 160)}`);
    }
  }
  return result;
}

async function deleteFiles(fileNames: string[]) {
  await Promise.all(
    fileNames.map((fileName) => unlink(path.join(uploadDirectory(), fileName)).catch(() => undefined)),
  );
}

async function uniqueProductSlug(title: string) {
  const base = slugify(title);
  let candidate = base;
  let suffix = 1;
  while (await prisma.product.findUnique({ where: { slug: candidate } })) {
    suffix += 1;
    candidate = `${base}-${suffix}`;
  }
  return candidate;
}

function descriptionWithMetadata(model: MakerWorldModel) {
  const details = [
    model.author ? `Автор моделі: ${model.author}.` : "",
    model.metadata.length > 0 ? `Дані моделі: ${model.metadata.join(" · ")}.` : "",
  ].filter(Boolean);
  return cleanText([model.description, ...details].join("\n\n"), 8000);
}

async function createDraft(chatId: string, model: MakerWorldModel) {
  const category =
    (await prisma.category.findUnique({ where: { slug: "inshe" } })) ||
    (await prisma.category.findFirst({ orderBy: [{ isVisible: "desc" }, { sortOrder: "asc" }] }));
  if (!category) throw new Error("У каталозі немає категорії для нової моделі.");

  const [settings, existingProduct, downloadedImages, slug] = await Promise.all([
    prisma.siteSetting.findUnique({ where: { id: 1 } }),
    prisma.product.findFirst({
      where: { sourceModelUrl: model.sourceUrl, status: ProductStatus.published },
      orderBy: { updatedAt: "desc" },
    }),
    downloadModelImages(model),
    uniqueProductSlug(model.title),
  ]);
  const siteDescription = descriptionWithMetadata(model);

  try {
    const draft = await prisma.product.create({
      data: {
        title: model.title,
        slug,
        categoryId: category.id,
        shortDescription: shortText(model.summary, 220),
        fullDescription: siteDescription,
        status: ProductStatus.draft,
        basePrice: null,
        priceFrom: false,
        leadTime: settings?.leadTimeNote || "Від кількох годин до 3 днів залежно від складності.",
        materialNote: model.metadata[0] || settings?.materialsNote || "Матеріал і колір узгоджуються перед друком.",
        deliveryNote: settings?.deliveryNote || "Доставка по Україні Новою поштою.",
        paymentNote: settings?.paymentNote || "Реквізити для оплати надійдуть після підтвердження замовлення.",
        sourceModelUrl: model.sourceUrl,
        images: {
          create: downloadedImages.map((image, index) => ({
            fileName: image.fileName,
            urlPath: image.urlPath,
            alt: `${model.title} — фото ${index + 1}`,
            sortOrder: (index + 1) * 10,
            isCover: index === 0,
          })),
        },
      },
      include: { images: { orderBy: [{ sortOrder: "asc" }, { id: "asc" }] } },
    });

    const session: DraftSession = {
      chatId,
      draftProductId: draft.id,
      existingProductId: existingProduct?.id || null,
      publishedProductId: null,
      publishedSlug: null,
      sourceUrl: model.sourceUrl,
      title: model.title,
      siteDescription,
      telegramSummary: shortText(model.summary, 500),
      metadata: model.metadata,
      author: model.author,
      price: null,
      images: draft.images.map((image, index) => ({
        id: image.id,
        fileName: image.fileName,
        urlPath: image.urlPath,
        sourceIndex: downloadedImages[index]?.sourceIndex || index + 1,
        selected: true,
      })),
      awaiting: null,
      manualSetup: null,
      postSent: false,
    };
    sessions.set(chatId, session);
    return session;
  } catch (error) {
    await deleteFiles(downloadedImages.map((image) => image.fileName));
    throw error;
  }
}

async function materializeManualDraft(session: DraftSession) {
  const category =
    (await prisma.category.findUnique({ where: { slug: "inshe" } })) ||
    (await prisma.category.findFirst({ orderBy: [{ isVisible: "desc" }, { sortOrder: "asc" }] }));
  if (!category) throw new Error("У каталозі немає категорії для нової моделі.");

  const [settings, existingProduct, slug] = await Promise.all([
    prisma.siteSetting.findUnique({ where: { id: 1 } }),
    prisma.product.findFirst({
      where: { sourceModelUrl: session.sourceUrl, status: ProductStatus.published },
      orderBy: { updatedAt: "desc" },
    }),
    uniqueProductSlug(session.title),
  ]);
  session.telegramSummary = firstSentenceForDraft(session.siteDescription);
  const draft = await prisma.product.create({
    data: {
      title: session.title,
      slug,
      categoryId: category.id,
      shortDescription: shortText(session.telegramSummary, 220),
      fullDescription: session.siteDescription,
      status: ProductStatus.draft,
      basePrice: null,
      priceFrom: false,
      leadTime: settings?.leadTimeNote || "Від кількох годин до 3 днів залежно від складності.",
      materialNote: settings?.materialsNote || "Матеріал і колір узгоджуються перед друком.",
      deliveryNote: settings?.deliveryNote || "Доставка по Україні Новою поштою.",
      paymentNote: settings?.paymentNote || "Реквізити для оплати надійдуть після підтвердження замовлення.",
      sourceModelUrl: session.sourceUrl,
    },
  });
  session.draftProductId = draft.id;
  session.existingProductId = existingProduct?.id || null;
  session.awaiting = null;
  session.manualSetup = null;
  return session;
}

function firstSentenceForDraft(value: string) {
  const normalized = cleanText(value, 500);
  return normalized.match(/^[\s\S]{1,220}?(?:[.!?](?=\s|$)|$)/)?.[0]?.trim() || normalized.slice(0, 220);
}

function selectedImages(session: DraftSession) {
  return session.images.filter((image) => image.selected);
}

function priceLabel(price: number | null) {
  return price == null ? "не вказано" : `${new Intl.NumberFormat("uk-UA").format(price)} грн`;
}

function telegramPostText(session: DraftSession, contactLink: string, channelLink: string) {
  const lines = [
    `✦ <b>${escapeHtml(session.title)}</b>`,
    "",
    `🧩 ${escapeHtml(session.telegramSummary)}`,
    "",
    `💰 <b>${escapeHtml(priceLabel(session.price))}</b>`,
    "◾ Акуратний і міцний 3D-друк під ваше замовлення.",
    "",
  ];
  lines.push(
    contactLink
      ? `📩 <a href="${escapeHtml(contactLink)}"><b>ЗАМОВИТИ</b></a>`
      : "📩 <b>ЗАМОВИТИ</b>",
  );
  if (channelLink) {
    lines.push(`✦ <a href="${escapeHtml(channelLink)}"><b>NARADA DRUK</b></a>`);
  }
  return lines.join("\n");
}

async function showPreview(session: DraftSession, includeAlbum = false) {
  const chosen = selectedImages(session);
  if (includeAlbum && chosen.length > 0) {
    await sendPhotoSet(session.chatId, chosen, session.title).catch(async (error) => {
      const message = error instanceof Error ? error.message : "невідома помилка";
      await sendMessage(session.chatId, `Не вдалося показати альбом: ${escapeHtml(shortText(message, 240))}`);
    });
  }
  const { contactLink, channelLink } = await contactAndChannelLinks();
  const photoState = session.images.length === 0
    ? "немає доступних публічних фото"
    : session.images.map((image, index) => `${image.selected ? "✅" : "▫️"}${index + 1}`).join("  ");
  const replacement = session.existingProductId
    ? "\n♻️ Після підтвердження буде оновлено наявний товар із цього джерела."
    : "";
  const preview = [
    `<b>Чернетка товару #${session.draftProductId}</b>${replacement}`,
    "",
    `<b>Назва:</b> ${escapeHtml(session.title)}`,
    `<b>Ціна:</b> ${escapeHtml(priceLabel(session.price))}`,
    `<b>Фото:</b> ${photoState}`,
    `<b>Джерело:</b> <a href="${escapeHtml(session.sourceUrl)}">MakerWorld</a>`,
    "",
    `<b>Опис сторінки товару:</b>\n${escapeHtml(shortText(session.siteDescription, 1200))}`,
    "",
    `<b>Окремий Telegram-допис:</b>\n${telegramPostText(session, contactLink, channelLink)}`,
    "",
    "Редагування: /title, /description, /summary, /images, /price. Потім /publish або /cancel.",
  ].join("\n");
  await sendMessage(session.chatId, preview, editorKeyboard());
}

async function syncDraft(session: DraftSession) {
  if (session.publishedProductId) return;
  await prisma.product.update({
    where: { id: session.draftProductId },
    data: {
      title: session.title,
      shortDescription: shortText(session.telegramSummary, 220),
      fullDescription: session.siteDescription,
      basePrice: session.price,
    },
  });
}

function parseImageSelection(value: string, maximum: number) {
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "all" || trimmed === "усі" || trimmed === "всі") {
    return new Set(Array.from({ length: maximum }, (_value, index) => index + 1));
  }
  const numbers = trimmed
    .split(/[\s,;]+/)
    .filter(Boolean)
    .map(Number);
  if (numbers.length === 0 || numbers.some((number) => !Number.isInteger(number) || number < 1 || number > maximum)) {
    throw new Error(`Вкажіть номери від 1 до ${maximum}, наприклад: 1, 3, 4.`);
  }
  return new Set(numbers);
}

async function assertSelectedDraftImages(session: DraftSession, chosen: DraftImage[]) {
  if (chosen.length === 0) return;
  const chosenIds = chosen.map((image) => image.id);
  const persisted = await prisma.productImage.findMany({
    where: { productId: session.draftProductId, id: { in: chosenIds } },
  });
  if (persisted.length !== chosenIds.length) {
    throw new Error("Не всі вибрані фото прикріплені до чернетки. Додайте фото ще раз перед публікацією.");
  }

  const persistedById = new Map(persisted.map((image) => [image.id, image]));
  for (const selected of chosen) {
    const image = persistedById.get(selected.id);
    if (!image || image.fileName !== selected.fileName) {
      throw new Error("Зв’язок вибраного фото з чернеткою пошкоджений. Додайте фото ще раз перед публікацією.");
    }
    const canonicalUrlPath = `/uploads/${image.fileName}`;
    if (image.urlPath !== canonicalUrlPath) {
      await prisma.productImage.update({
        where: { id: image.id },
        data: { urlPath: canonicalUrlPath },
      });
      selected.urlPath = canonicalUrlPath;
    }
    try {
      await access(path.join(uploadDirectory(), image.fileName));
    } catch {
      throw new Error(`Файл вибраного фото ${image.id} відсутній у сховищі. Завантажте це фото ще раз.`);
    }
  }
}

async function finalizeProduct(session: DraftSession) {
  const chosen = selectedImages(session);
  if (!session.price || session.price <= 0) throw new Error("Спочатку вкажіть ціну кнопкою «Ціна» або /price 450.");
  await assertSelectedDraftImages(session, chosen);
  const chosenIds = chosen.map((image) => image.id);
  const removed = session.images.filter((image) => !image.selected);

  if (session.existingProductId) {
    const [existing, draft] = await Promise.all([
      prisma.product.findUnique({
        where: { id: session.existingProductId },
        include: { images: true },
      }),
      prisma.product.findUnique({ where: { id: session.draftProductId } }),
    ]);
    if (!existing) throw new Error("Товар для оновлення більше не існує.");
    if (!draft) throw new Error("Чернетку більше не знайдено.");

    const saved = await prisma.$transaction(async (transaction) => {
      await transaction.productImage.deleteMany({ where: { productId: existing.id } });
      await transaction.productImage.deleteMany({
        where: {
          productId: session.draftProductId,
          ...(chosenIds.length > 0 ? { id: { notIn: chosenIds } } : {}),
        },
      });
      if (chosenIds.length > 0) {
        await transaction.productImage.updateMany({
          where: { productId: session.draftProductId, id: { in: chosenIds } },
          data: {
            productId: existing.id,
            isCover: false,
            alt: `${session.title} — фото товару`,
          },
        });
        await transaction.productImage.update({ where: { id: chosenIds[0] }, data: { isCover: true } });
        const attachedCount = await transaction.productImage.count({
          where: { productId: existing.id, id: { in: chosenIds } },
        });
        if (attachedCount !== chosenIds.length) throw new Error("Не вдалося прикріпити всі фото до товару.");
      }
      await transaction.productVariant.deleteMany({ where: { productId: existing.id } });
      const updated = await transaction.product.update({
        where: { id: existing.id },
        data: {
          title: session.title,
          categoryId: draft.categoryId,
          shortDescription: shortText(session.telegramSummary, 220),
          fullDescription: session.siteDescription,
          status: ProductStatus.published,
          basePrice: session.price,
          priceFrom: false,
          leadTime: draft.leadTime,
          materialNote: draft.materialNote,
          deliveryNote: draft.deliveryNote,
          paymentNote: draft.paymentNote,
          sourceModelUrl: session.sourceUrl,
        },
      });
      await transaction.product.delete({ where: { id: session.draftProductId } });
      return updated;
    });
    await deleteFiles([...existing.images.map((image) => image.fileName), ...removed.map((image) => image.fileName)]);
    return saved;
  }

  const saved = await prisma.$transaction(async (transaction) => {
    await transaction.productImage.deleteMany({
      where: {
        productId: session.draftProductId,
        ...(chosenIds.length > 0 ? { id: { notIn: chosenIds } } : {}),
      },
    });
    if (chosenIds.length > 0) {
      await transaction.productImage.updateMany({
        where: { productId: session.draftProductId, id: { in: chosenIds } },
        data: { isCover: false, alt: `${session.title} — фото товару` },
      });
      await transaction.productImage.update({ where: { id: chosenIds[0] }, data: { isCover: true } });
      const attachedCount = await transaction.productImage.count({
        where: { productId: session.draftProductId, id: { in: chosenIds } },
      });
      if (attachedCount !== chosenIds.length) throw new Error("Не вдалося зберегти всі фото товару.");
    }
    return transaction.product.update({
      where: { id: session.draftProductId },
      data: {
        title: session.title,
        shortDescription: shortText(session.telegramSummary, 220),
        fullDescription: session.siteDescription,
        status: ProductStatus.published,
        basePrice: session.price,
        priceFrom: false,
      },
    });
  });
  await deleteFiles(removed.map((image) => image.fileName));
  return saved;
}

async function publishProductPost(session: DraftSession) {
  if (!/^-?[1-9]\d*$/.test(postsChatId)) {
    throw new Error("Вкажіть числовий NARADADRUK_POSTS_TELEGRAM_CHAT_ID. Чернетка залишається неопублікованою.");
  }

  const { contactLink, channelLink } = await contactAndChannelLinks();

  if (!session.publishedProductId || !session.publishedSlug) {
    const product = await finalizeProduct(session);
    session.publishedProductId = product.id;
    session.publishedSlug = product.slug;
    session.draftProductId = product.id;
  }

  const productUrl = publicProductUrl(session.publishedSlug);
  const inlineKeyboard = [
    [{ text: "Замовити на сайті", url: productUrl }],
  ];
  if (!session.postSent) {
    const caption = telegramPostText(session, contactLink, channelLink);
    const primaryImage = selectedImages(session)[0];
    if (primaryImage) {
      const form = new FormData();
      const buffer = await readFile(path.join(uploadDirectory(), primaryImage.fileName));
      form.set("chat_id", postsChatId);
      form.set("photo", new Blob([new Uint8Array(buffer)], { type: mimeTypeForFile(primaryImage.fileName) }), primaryImage.fileName);
      form.set("caption", caption);
      form.set("parse_mode", "HTML");
      form.set("reply_markup", JSON.stringify({ inline_keyboard: inlineKeyboard }));
      await telegramMultipart("sendPhoto", form);
    } else {
      await telegramJson("sendMessage", {
        chat_id: postsChatId,
        text: caption,
        parse_mode: "HTML",
        disable_web_page_preview: true,
        reply_markup: { inline_keyboard: inlineKeyboard },
      });
    }
    session.postSent = true;
  }
  return { productUrl };
}

async function cancelSession(session: DraftSession) {
  if (session.publishedProductId) {
    sessions.delete(session.chatId);
    return "Повторну публікацію скасовано. Товар уже активний на сайті й не видалений.";
  }
  const images = await prisma.productImage.findMany({ where: { productId: session.draftProductId } });
  const deleted = await prisma.product.deleteMany({
    where: { id: session.draftProductId, status: ProductStatus.draft },
  });
  if (deleted.count > 0) {
    await deleteFiles(images.map((image) => image.fileName));
  }
  sessions.delete(session.chatId);
  return "Чернетку скасовано й видалено. Можна почати знову командою /makerworld.";
}

function helpText() {
  return [
    "<b>Narada Druk — керування</b>",
    "/orders — активні замовлення та їх статуси",
    "/manual — створити ручне замовлення з чату",
    "",
    "<b>MakerWorld → Narada Druk</b>",
    "/makerworld — почати й надіслати публічне посилання на модель",
    "/title Нова назва — змінити назву",
    "/description Повний опис — змінити розгорнутий опис сторінки товару",
    "/summary Короткий текст — окремо змінити Telegram-опис",
    "/images 1,3,4 — залишити вибрані фото",
    "/price 450 — встановити ціну у гривнях",
    "/preview — оновити превʼю",
    "/publish — активувати товар і опублікувати пост",
    "/cancel — видалити неопубліковану чернетку",
    "",
    `Якщо MakerWorld відхиляє серверне читання, кнопка ручної чернетки збере назву й опис. Після цього надішліть до ${maxImages} фото прямо в чат.`,
    "",
    "До фінального підтвердження товар має статус draft і не видимий покупцям.",
  ].join("\n");
}

const orderStatusText = { new: "Обробляється", accepted: "Прийнято в роботу", shipped: "Відправлено", closed: "Закрито" } as const;
function orderStatusLabel(status: string) {
  if (status === "confirmed" || status === "processing") return orderStatusText.accepted;
  if (status === "completed" || status === "cancelled") return orderStatusText.closed;
  return orderStatusText[status as keyof typeof orderStatusText] ?? status;
}
const paymentText = { cash_on_delivery: "Післяплата", transfer: "Переказ після підтвердження" } as const;

function money(value: number) { return `${new Intl.NumberFormat("uk-UA").format(value)} грн`; }
function orderNumber(publicId: string) { return publicId.slice(0, 8).toUpperCase(); }

async function showOrdersDashboard(chatId: string, replaceMessageId?: number) {
  const orders = await prisma.order.findMany({ where: { status: { in: ["new", "accepted", "shipped"] } }, include: { _count: { select: { items: true } } }, orderBy: { createdAt: "desc" }, take: 30 });
  const counts = { new: 0, accepted: 0, shipped: 0 };
  for (const order of orders) counts[order.status as keyof typeof counts] = (counts[order.status as keyof typeof counts] ?? 0) + 1;
  const text = [
    "<b>Активні замовлення Narada Druk</b>",
    `Обробляється: <b>${counts.new}</b> · У роботі: <b>${counts.accepted}</b> · Відправлено: <b>${counts.shipped}</b>`,
    "",
    ...(orders.slice(0, 12).map((order) => `#${orderNumber(order.publicId)} · ${escapeHtml(order.firstName || "Без імені")} · ${money(order.total)} · ${orderStatusLabel(order.status)}`)),
    orders.length > 12 ? `\nЩе активних: ${orders.length - 12}` : "",
  ].filter(Boolean).join("\n");
  const keyboard = { inline_keyboard: [
    ...orders.slice(0, 10).map((order) => [{ text: `#${orderNumber(order.publicId)} · ${orderStatusLabel(order.status)}`, callback_data: `order:view:${order.publicId}` }]),
    [{ text: "Оновити", callback_data: "order:list" }, { text: "Створити вручну", callback_data: "manual:start" }],
  ] };
  const messageId = replaceMessageId ?? dashboardMessageId;
  if (messageId) {
    const edited = await telegramJson<TelegramMessage>("editMessageText", { chat_id: chatId, message_id: messageId, text, parse_mode: "HTML", disable_web_page_preview: true, reply_markup: keyboard }).catch(() => null);
    if (edited) { dashboardMessageId = messageId; return; }
  }
  const sent = await sendMessage(chatId, text, keyboard);
  dashboardMessageId = sent.message_id;
}

async function showOrderCard(chatId: string, publicId: string, replaceMessageId?: number) {
  const order = await prisma.order.findUnique({ where: { publicId }, include: { items: true, events: { orderBy: { createdAt: "desc" }, take: 10 } } });
  if (!order) { await sendMessage(chatId, "Замовлення не знайдено або його вже видалено."); return; }
  const destination = order.deliveryMethod === "courier" ? order.courierAddress : order.deliveryDestination;
  const text = [
    `<b>Замовлення #${orderNumber(order.publicId)}</b>`,
    `<b>Статус:</b> ${orderStatusLabel(order.status)}`,
    `<b>Джерело:</b> ${order.source === "manual" ? "ручне" : "сайт"}`,
    `<b>Створено:</b> ${new Intl.DateTimeFormat("uk-UA", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Kyiv" }).format(order.createdAt)}`,
    "",
    `<b>Клієнт:</b> ${escapeHtml(`${order.firstName} ${order.lastName}`.trim() || "Не вказано")}`,
    `<b>Контакт:</b> ${escapeHtml([order.phone, order.telegramContact].filter(Boolean).join(" · ") || "Не вказано")}`,
    ...order.items.slice(0, 12).map((item, index) => `${index + 1}. ${escapeHtml(shortText(item.productTitle, 100))}${item.variantLabel ? ` — ${escapeHtml(shortText(item.variantLabel, 70))}` : ""}\n${item.quantity} × ${money(item.unitPrice)} = <b>${money(item.totalPrice)}</b>`),
    order.items.length > 12 ? `Ще позицій: ${order.items.length - 12}` : "",
    order.saleDiscountAmount ? `<b>Знижка товарів:</b> −${money(order.saleDiscountAmount)}` : "",
    order.discountAmount ? `<b>Промокод ${escapeHtml(order.promoCodeSnapshot)}:</b> −${money(order.discountAmount)}` : "",
    `<b>Разом:</b> ${money(order.total)}`,
    `<b>Доставка:</b> ${escapeHtml([order.cityName, destination].filter(Boolean).join(" · ") || "Не вказано")}`,
    `<b>Оплата:</b> ${paymentText[order.paymentMethod]}`,
    order.comment ? `<b>Коментар клієнта:</b> ${escapeHtml(shortText(order.comment, 700))}` : "",
    order.events.length ? "\n<b>Остання історія:</b>" : "",
    ...order.events.slice(0, 6).map((event) => event.eventType === "comment" ? `• ${escapeHtml(shortText(event.comment, 280))}` : `• ${event.eventType === "created" ? "Створено" : orderStatusLabel(event.toStatus)}`),
  ].filter(Boolean).join("\n");
  const statusButtons = order.status === "new" ? [{ text: "Прийняти в роботу", callback_data: `order:status:${publicId}:accepted` }]
    : order.status === "accepted" ? [{ text: "Відправлено", callback_data: `order:status:${publicId}:shipped` }]
    : [];
  const keyboard = { inline_keyboard: [statusButtons, [{ text: "Додати коментар", callback_data: `order:comment:${publicId}` }], order.status !== "closed" ? [{ text: "Закрити", callback_data: `order:close:${publicId}` }] : [], [{ text: "До активних", callback_data: "order:list" }]].filter((row) => row.length > 0) };
  if (replaceMessageId) {
    const edited = await telegramJson("editMessageText", { chat_id: chatId, message_id: replaceMessageId, text, parse_mode: "HTML", disable_web_page_preview: true, reply_markup: keyboard }).catch(() => null);
    if (edited) return;
  }
  await sendMessage(chatId, text, keyboard);
}

async function changeOrderStatus(publicId: string, nextStatus: keyof typeof orderStatusText) {
  return prisma.$transaction(async (transaction) => {
    const order = await transaction.order.findUnique({ where: { publicId }, select: { id: true, status: true } });
    if (!order || order.status === nextStatus) return { order, changed: false };
    const allowed = (order.status === "new" && nextStatus === "accepted")
      || (order.status === "accepted" && nextStatus === "shipped")
      || (order.status !== "closed" && nextStatus === "closed");
    if (!allowed) return { order, changed: false };
    await transaction.order.update({ where: { id: order.id }, data: { status: nextStatus } });
    await transaction.orderEvent.create({ data: { orderId: order.id, eventType: "status", fromStatus: order.status, toStatus: nextStatus, actor: "telegram" } });
    return { order: { ...order, status: nextStatus }, changed: true };
  });
}

async function startManualOrder(chatId: string) {
  manualOrders.set(chatId, { step: "contact", name: "", contact: "", items: "", amount: 0, delivery: "", payment: "transfer" });
  await sendMessage(chatId, "<b>Ручне замовлення</b>\nНадішліть ім’я та контакт через вертикальну риску.\nНаприклад: <code>Олена | @olena або +380…</code>", { inline_keyboard: [[{ text: "Скасувати", callback_data: "manual:cancel" }]] });
}

async function createManualOrder(chatId: string, session: ManualOrderSession) {
  const [firstName, ...lastParts] = session.name.split(/\s+/);
  const order = await prisma.order.create({
    data: { publicId: randomUUID(), source: "manual", firstName: firstName || "Клієнт", lastName: lastParts.join(" "), comment: session.delivery, phone: session.contact, telegramContact: session.contact, cityName: "Ручне замовлення", deliveryMethod: "courier", deliveryDestination: session.delivery, courierAddress: session.delivery, paymentMethod: session.payment, subtotal: session.amount, total: session.amount,
      items: { create: { productSlug: "", productTitle: session.items, productUrl: "", quantity: 1, unitPrice: session.amount, regularUnitPrice: session.amount, totalPrice: session.amount } },
      events: { create: { eventType: "created", toStatus: "new", comment: "Створено власником у Telegram", actor: "telegram" } },
    }, include: { items: true },
  });
  manualOrders.delete(chatId);
  await showOrderCard(chatId, order.publicId);
}

function isAuthorizedOwnerChat(message: TelegramMessage, actorId = message.from?.id) {
  return String(message.chat.id) === ownerChatId && ownerUserIds.has(String(actorId ?? ""));
}

function splitCommand(text: string) {
  const match = text.trim().match(/^\/([a-z_]+)(?:@[a-zA-Z0-9_]+)?(?:\s+([\s\S]*))?$/i);
  return match ? { command: match[1].toLowerCase(), argument: (match[2] || "").trim() } : null;
}

async function requestField(session: DraftSession, field: Exclude<AwaitingField, null>) {
  if (field === "images" && session.images.length === 0) {
    session.awaiting = null;
    await sendMessage(
      session.chatId,
      `Надішліть фото товару звичайним Telegram-фото. Можна додати до ${maxImages} фото по одному або альбомом.`,
      editorKeyboard(),
    );
    return;
  }
  session.awaiting = field;
  const prompts: Record<Exclude<AwaitingField, null>, string> = {
    url: "Надішліть публічне HTTPS-посилання на модель MakerWorld.",
    title: "Надішліть нову назву товару (до 140 символів).",
    description: "Надішліть повний опис для сторінки товару. Він зберігається окремо від Telegram-тексту.",
    summary: "Надішліть короткий Telegram-текст про головну користь виробу (до 500 символів).",
    images: `Надішліть номери фото, які слід залишити, наприклад: 1, 3, 4. Доступно: ${session.images.length}.`,
    price: "Надішліть ціну у гривнях одним числом, наприклад: 450.",
  };
  await sendMessage(session.chatId, prompts[field]);
}

async function applyFieldValue(session: DraftSession, field: Exclude<AwaitingField, "url" | null>, raw: string) {
  if (field === "title") {
    const value = cleanText(raw, 140);
    if (value.length < 3) throw new Error("Назва має містити щонайменше 3 символи.");
    session.title = value;
  } else if (field === "description") {
    const value = cleanText(raw, 8000);
    if (value.length < 20) throw new Error("Опис для сайту має містити щонайменше 20 символів.");
    session.siteDescription = value;
  } else if (field === "summary") {
    const value = cleanText(raw, 500);
    if (value.length < 10) throw new Error("Telegram-текст має містити щонайменше 10 символів.");
    session.telegramSummary = value;
  } else if (field === "images") {
    if (session.images.length === 0) throw new Error("MakerWorld не надав доступних фото для вибору.");
    const selected = parseImageSelection(raw, session.images.length);
    session.images.forEach((image, index) => { image.selected = selected.has(index + 1); });
  } else if (field === "price") {
    const normalized = raw.replace(/[\s₴грн.,]/gi, "");
    const price = Number(normalized);
    if (!Number.isInteger(price) || price < 1 || price > 10_000_000) {
      throw new Error("Вкажіть цілу ціну від 1 до 10 000 000 грн.");
    }
    session.price = price;
  }
  session.awaiting = null;
  await syncDraft(session);
  await showPreview(session, field === "images");
}

async function handleMakerWorldUrl(chatId: string, value: string) {
  await sendMessage(chatId, "Отримую публічні дані MakerWorld і готую неопубліковану чернетку…");
  let sourceUrl = "";
  try {
    sourceUrl = parseMakerWorldUrl(value).toString();
    const model = await fetchMakerWorldModel(value);
    const session = await createDraft(chatId, model);
    const imageNote = session.images.length > 0
      ? `Збережено ${session.images.length} фото. Усі вибрані за замовчуванням.`
      : "Публічних фото не знайдено. Чернетку створено, але без фото її не можна опублікувати.";
    await sendMessage(chatId, `Чернетку #${session.draftProductId} створено. ${imageNote}`);
    await showPreview(session, true);
  } catch (error) {
    const message = error instanceof MakerWorldFetchError || error instanceof Error
      ? error.message
      : "Не вдалося обробити модель MakerWorld.";
    const session: DraftSession = {
      chatId,
      draftProductId: 0,
      existingProductId: null,
      publishedProductId: null,
      publishedSlug: null,
      sourceUrl,
      title: "",
      siteDescription: "",
      telegramSummary: "",
      metadata: [],
      author: "",
      price: null,
      images: [],
      awaiting: "url",
      manualSetup: null,
      postSent: false,
    };
    sessions.set(chatId, session);
    const rejectedStatus = message.match(/HTTP\s+(403|429)\b/i)?.[1];
    const guidance = rejectedStatus
      ? `MakerWorld відхилив автоматичне читання цієї сторінки (HTTP ${rejectedStatus}). Це може бути захист сайту або обмеження для серверної мережі; ми не обходимо такі перевірки.`
      : `Не вдалося створити чернетку: ${escapeHtml(shortText(message, 500))}`;
    const keyboard = sourceUrl
      ? {
          inline_keyboard: [
            [{ text: "📝 Заповнити чернетку вручну", callback_data: "mw:manual" }],
            [{ text: "✖️ Скасувати", callback_data: "mw:cancel" }],
          ],
        }
      : undefined;
    await sendMessage(
      chatId,
      `${guidance}\n\n${sourceUrl ? "Можна зберегти це посилання як джерело й вручну додати назву, опис, фото та ціну." : "Перевірте публічне посилання MakerWorld або надішліть інше."}`,
      keyboard,
    );
  }
}

async function handleMessage(message: TelegramMessage) {
  if (!isAuthorizedOwnerChat(message)) return;
  if (!message.text && message.caption) message.text = message.caption;
  const chatId = String(message.chat.id);
  let session = sessions.get(chatId);

  if (message.photo?.length) {
    if (!session || session.draftProductId <= 0) {
      await sendMessage(chatId, "Спочатку створіть чернетку: завершіть назву й опис або почніть із /makerworld.");
      return;
    }
    const photo = [...message.photo].sort((left, right) => (right.width * right.height) - (left.width * left.height))[0];
    try {
      await addTelegramPhotoToDraft(session, photo);
      await sendMessage(
        chatId,
        `Фото додано (${session.images.length}/${maxImages}). Надішліть ще фото або встановіть ціну й перевірте /preview.`,
        editorKeyboard(),
      );
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Не вдалося додати фото.";
      await sendMessage(chatId, escapeHtml(shortText(errorMessage, 400)), editorKeyboard());
    }
    return;
  }

  if (!message.text) return;
  const command = splitCommand(message.text);

  if (command?.command === "orders") {
    await showOrdersDashboard(chatId);
    return;
  }
  if (command?.command === "manual") {
    await startManualOrder(chatId);
    return;
  }

  const commentOrderId = awaitingOrderComments.get(chatId);
  if (commentOrderId) {
    if (command?.command === "cancel") {
      awaitingOrderComments.delete(chatId);
      await sendMessage(chatId, "Додавання коментаря скасовано.");
      return;
    }
    const comment = cleanText(message.text, 1000);
    if (comment.length < 2) { await sendMessage(chatId, "Коментар закороткий. Надішліть щонайменше 2 символи або /cancel."); return; }
    const order = await prisma.order.findUnique({ where: { publicId: commentOrderId }, select: { id: true, status: true } });
    if (order) await prisma.orderEvent.create({ data: { orderId: order.id, eventType: "comment", toStatus: order.status, comment, actor: "telegram" } });
    awaitingOrderComments.delete(chatId);
    await showOrderCard(chatId, commentOrderId);
    return;
  }

  const manual = manualOrders.get(chatId);
  if (manual) {
    if (command?.command === "cancel") {
      manualOrders.delete(chatId);
      await sendMessage(chatId, "Створення ручного замовлення скасовано.");
      return;
    }
    if (manual.step === "contact") {
      const [name, contact] = message.text.split("|").map((value) => cleanText(value || "", 120));
      if (!name || !contact) { await sendMessage(chatId, "Використайте формат <code>Ім’я | контакт</code> або /cancel."); return; }
      Object.assign(manual, { name, contact, step: "items" as const });
      await sendMessage(chatId, "Опишіть товар або склад замовлення одним повідомленням (до 500 символів)."); return;
    }
    if (manual.step === "items") {
      const items = cleanText(message.text, 500);
      if (items.length < 3) { await sendMessage(chatId, "Опис товару закороткий."); return; }
      Object.assign(manual, { items, step: "amount" as const });
      await sendMessage(chatId, "Вкажіть загальну суму в гривнях одним числом. Якщо ще невідома — надішліть <code>0</code>."); return;
    }
    if (manual.step === "amount") {
      const amount = Number(message.text.replace(/\s|грн/gi, ""));
      if (!Number.isInteger(amount) || amount < 0 || amount > 10_000_000) { await sendMessage(chatId, "Вкажіть цілу суму від 0 до 10 000 000 грн."); return; }
      Object.assign(manual, { amount, step: "delivery" as const });
      await sendMessage(chatId, "Додайте спосіб/адресу доставки або іншу примітку для виконання."); return;
    }
    if (manual.step === "delivery") {
      Object.assign(manual, { delivery: cleanText(message.text, 500), step: "payment" as const });
      await sendMessage(chatId, "Оберіть спосіб оплати.", { inline_keyboard: [[{ text: "Переказ після підтвердження", callback_data: "manual:payment:transfer" }, { text: "Післяплата", callback_data: "manual:payment:cash_on_delivery" }], [{ text: "Скасувати", callback_data: "manual:cancel" }]] }); return;
    }
    await sendMessage(chatId, "Завершіть дію кнопками в попередньому повідомленні або /cancel.");
    return;
  }

  if (command?.command === "help" || command?.command === "start") {
    await sendMessage(chatId, helpText());
    return;
  }

  if (command?.command === "makerworld") {
    if (session) {
      await sendMessage(chatId, "У вас уже є активна чернетка. Опублікуйте її або використайте /cancel.", editorKeyboard());
      return;
    }
    if (command.argument) {
      await handleMakerWorldUrl(chatId, command.argument);
      return;
    }
    await sendMessage(chatId, "Надішліть публічне HTTPS-посилання на модель MakerWorld. /cancel — скасувати.");
    sessions.set(chatId, {
      chatId,
      draftProductId: 0,
      existingProductId: null,
      publishedProductId: null,
      publishedSlug: null,
      sourceUrl: "",
      title: "",
      siteDescription: "",
      telegramSummary: "",
      metadata: [],
      author: "",
      price: null,
      images: [],
      awaiting: "url",
      manualSetup: null,
      postSent: false,
    });
    return;
  }

  if (command?.command === "cancel" && session) {
    if (session.draftProductId <= 0) {
      sessions.delete(chatId);
      await sendMessage(chatId, "Дію скасовано. Можна почати знову командою /makerworld.");
    } else {
      await sendMessage(chatId, escapeHtml(await cancelSession(session)));
    }
    return;
  }

  if (session?.awaiting === "url") {
    sessions.delete(chatId);
    await handleMakerWorldUrl(chatId, command?.argument || message.text);
    return;
  }

  if (session?.manualSetup) {
    if (command) {
      await sendMessage(chatId, "Завершіть ручне створення чернетки поточним полем або використайте /cancel.");
      return;
    }
    try {
      if (session.manualSetup === "title") {
        const title = cleanText(message.text, 140);
        if (title.length < 3) throw new Error("Назва має містити щонайменше 3 символи.");
        session.title = title;
        session.manualSetup = "description";
        await sendMessage(chatId, "Надішліть повний опис для сторінки товару (щонайменше 20 символів). Джерельне посилання MakerWorld буде збережене окремо.");
        return;
      }

      const description = cleanText(message.text, 8000);
      if (description.length < 20) throw new Error("Опис для сайту має містити щонайменше 20 символів.");
      session.siteDescription = description;
      await materializeManualDraft(session);
      await sendMessage(
        chatId,
        `Чернетку #${session.draftProductId} створено й приховано від покупців. Тепер надішліть до ${maxImages} фото звичайним Telegram-фото, потім встановіть ціну та перевірте превʼю.`,
        editorKeyboard(),
      );
      return;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Не вдалося створити ручну чернетку.";
      await sendMessage(chatId, escapeHtml(shortText(errorMessage, 500)));
      return;
    }
  }

  if (!session) {
    await sendMessage(chatId, "Почніть командою /makerworld. /help покаже всі доступні дії.");
    return;
  }

  if (command?.command === "preview") {
    await showPreview(session, true);
    return;
  }

  if (command?.command === "publish") {
    try {
      const { productUrl } = await publishProductPost(session);
      sessions.delete(chatId);
      await sendMessage(chatId, `Готово: товар активний, а пост опублікований одним повідомленням.\n<a href="${escapeHtml(productUrl)}">Відкрити сторінку товару</a>`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Не вдалося опублікувати товар.";
      const stateNote = session.publishedProductId
        ? "Товар уже активний на сайті, але Telegram-допис не підтверджено. Повторіть /publish."
        : "Чернетку збережено. Виправте налаштування або дані й повторіть /publish.";
      await sendMessage(chatId, `${escapeHtml(shortText(message, 500))}\n${stateNote}`, editorKeyboard());
    }
    return;
  }

  const commandToField: Record<string, Exclude<AwaitingField, "url" | null>> = {
    title: "title",
    description: "description",
    summary: "summary",
    images: "images",
    price: "price",
  };
  const field = command ? commandToField[command.command] : null;
  if (field) {
    if (!command?.argument) {
      await requestField(session, field);
      return;
    }
    try {
      await applyFieldValue(session, field, command.argument);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Некоректне значення.";
      await sendMessage(chatId, escapeHtml(message), editorKeyboard());
    }
    return;
  }

  if (session.awaiting) {
    try {
      await applyFieldValue(session, session.awaiting as Exclude<AwaitingField, "url" | null>, message.text);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : "Некоректне значення.";
      await sendMessage(chatId, escapeHtml(errorMessage), editorKeyboard());
    }
    return;
  }

  await sendMessage(chatId, "Оберіть поле кнопкою або скористайтеся /help.", editorKeyboard());
}

async function handleCallback(callback: TelegramCallbackQuery) {
  const message = callback.message;
  if (!message || !isAuthorizedOwnerChat(message, callback.from.id)) {
    await answerCallback(callback.id, "Доступ заборонено.");
    return;
  }
  const chatId = String(message.chat.id);
  if (callback.data === "order:list") {
    await answerCallback(callback.id);
    await showOrdersDashboard(chatId, message.message_id);
    return;
  }
  if (callback.data?.startsWith("order:")) {
    const [, action, publicId, value] = callback.data.split(":");
    if (!/^[0-9a-f-]{36}$/i.test(publicId || "")) { await answerCallback(callback.id, "Некоректне замовлення."); return; }
    if (action === "view") {
      await answerCallback(callback.id);
      await showOrderCard(chatId, publicId, message.message_id);
    } else if (action === "status" && ["accepted", "shipped"].includes(value)) {
      const result = await changeOrderStatus(publicId, value as "accepted" | "shipped");
      await answerCallback(callback.id, result.changed ? "Статус оновлено." : "Кнопка вже неактуальна.");
      await showOrderCard(chatId, publicId, message.message_id);
    } else if (action === "comment") {
      awaitingOrderComments.set(chatId, publicId);
      await answerCallback(callback.id);
      await sendMessage(chatId, `Надішліть внутрішній коментар для #${orderNumber(publicId)}. /cancel — скасувати.`);
    } else if (action === "close") {
      await answerCallback(callback.id);
      await sendMessage(chatId, `Закрити замовлення #${orderNumber(publicId)}? Це прибере його з активного списку.`, { inline_keyboard: [[{ text: "Так, закрити", callback_data: `order:confirmclose:${publicId}` }, { text: "Назад", callback_data: `order:view:${publicId}` }]] });
    } else if (action === "confirmclose") {
      const result = await changeOrderStatus(publicId, "closed");
      await answerCallback(callback.id, result.changed ? "Замовлення закрито." : "Замовлення вже закрито або кнопка неактуальна.");
      await showOrderCard(chatId, publicId, message.message_id);
    } else {
      await answerCallback(callback.id, "Дія вже неактуальна.");
    }
    return;
  }
  if (callback.data === "manual:start") {
    await answerCallback(callback.id);
    await startManualOrder(chatId);
    return;
  }
  if (callback.data?.startsWith("manual:")) {
    const [, action, value] = callback.data.split(":");
    const manual = manualOrders.get(chatId);
    if (action === "cancel") {
      manualOrders.delete(chatId);
      await answerCallback(callback.id, "Скасовано.");
      return;
    }
    if (!manual) { await answerCallback(callback.id, "Чернетка вже неактуальна."); return; }
    if (action === "payment" && ["transfer", "cash_on_delivery"].includes(value)) {
      manual.payment = value as ManualOrderSession["payment"];
      manual.step = "confirm";
      await answerCallback(callback.id);
      await sendMessage(chatId, [`<b>Перевірте ручне замовлення</b>`, `Клієнт: ${escapeHtml(manual.name)} · ${escapeHtml(manual.contact)}`, `Товар: ${escapeHtml(manual.items)}`, `Сума: ${money(manual.amount)}`, `Доставка/примітка: ${escapeHtml(manual.delivery)}`, `Оплата: ${paymentText[manual.payment]}`].join("\n"), { inline_keyboard: [[{ text: "Створити", callback_data: "manual:confirm" }, { text: "Скасувати", callback_data: "manual:cancel" }]] });
      return;
    }
    if (action === "confirm" && manual.step === "confirm") {
      await answerCallback(callback.id, "Створюю замовлення.");
      await createManualOrder(chatId, manual);
      return;
    }
    await answerCallback(callback.id, "Дія вже неактуальна.");
    return;
  }
  if (callback.data?.startsWith("review:")) {
    const [, action, rawId] = callback.data.split(":");
    const reviewId = Number(rawId);
    if (!Number.isInteger(reviewId) || !["approve", "delete"].includes(action)) {
      await answerCallback(callback.id, "Некоректна дія.");
      return;
    }
    let changedCount = 0;
    if (action === "approve") {
      const changed = await prisma.review.updateMany({ where: { id: reviewId, status: ReviewStatus.pending }, data: { status: ReviewStatus.approved, moderatedAt: new Date() } });
      changedCount = changed.count;
    } else {
      const review = await prisma.review.findFirst({ where: { id: reviewId, status: ReviewStatus.pending }, include: { images: true } });
      if (review) {
        await prisma.review.delete({ where: { id: review.id } });
        await deleteFiles(review.images.map((image) => image.fileName));
        changedCount = 1;
      }
    }
    await telegramJson("editMessageReplyMarkup", {
      chat_id: chatId,
      message_id: message.message_id,
      reply_markup: { inline_keyboard: [] },
    }).catch(() => undefined);
    await answerCallback(
      callback.id,
      changedCount > 0
        ? action === "approve" ? "Відгук опубліковано." : "Відгук видалено."
        : "Відгук уже опрацьовано або видалено.",
    );
    return;
  }
  const session = sessions.get(chatId);
  if (callback.data === "mw:manual" && session && session.draftProductId <= 0 && session.sourceUrl) {
    session.awaiting = null;
    session.manualSetup = "title";
    await answerCallback(callback.id, "Переходимо до ручної чернетки.");
    await sendMessage(chatId, "Надішліть назву товару (від 3 до 140 символів). /cancel — скасувати.");
    return;
  }
  if (callback.data === "mw:cancel" && session && session.draftProductId <= 0) {
    sessions.delete(chatId);
    await answerCallback(callback.id, "Скасовано.");
    await telegramJson("editMessageReplyMarkup", {
      chat_id: chatId,
      message_id: message.message_id,
      reply_markup: { inline_keyboard: [] },
    }).catch(() => undefined);
    return;
  }
  if (!session || session.draftProductId <= 0) {
    await answerCallback(callback.id, "Активної чернетки немає.");
    return;
  }

  const action = callback.data?.replace(/^mw:/, "") || "";
  await answerCallback(callback.id);
  if (action === "preview") {
    await showPreview(session, true);
  } else if (action === "publish") {
    await handleMessage({ ...message, from: callback.from, text: "/publish" });
  } else if (action === "cancel") {
    await handleMessage({ ...message, from: callback.from, text: "/cancel" });
  } else if (["title", "description", "summary", "images", "price"].includes(action)) {
    await requestField(session, action as Exclude<AwaitingField, "url" | null>);
  }
}

async function configureCommands() {
  await telegramJson("setMyCommands", {
    commands: [
      { command: "orders", description: "Активні замовлення та керування статусами" },
      { command: "manual", description: "Створити ручне замовлення" },
      { command: "makerworld", description: "Створити товар із публічної моделі MakerWorld" },
      { command: "help", description: "Показати всі команди редагування" },
      { command: "preview", description: "Оновити превʼю активної чернетки" },
      { command: "title", description: "Змінити назву товару" },
      { command: "description", description: "Змінити повний опис для сайту" },
      { command: "summary", description: "Змінити окремий Telegram-текст" },
      { command: "images", description: "Вибрати фото для товару й альбому" },
      { command: "price", description: "Встановити ціну" },
      { command: "publish", description: "Активувати товар і опублікувати пост" },
      { command: "cancel", description: "Видалити неопубліковану чернетку" },
    ],
    scope: { type: "chat", chat_id: ownerChatId },
  });
}

async function run() {
  if (!botToken || !/^-?[1-9]\d*$/.test(ownerChatId)) {
    console.log("[owner-bot] disabled: order bot token or numeric configured chat ID is absent");
    return;
  }
  if (hasInvalidOwnerUserId || ownerUserIds.size === 0) {
    console.log("[owner-bot] disabled: positive owner user ID allowlist is missing or invalid");
    return;
  }

  await configureCommands();
  console.log("[owner-bot] started for the configured owner chat and actor allowlist");
  const pending = await telegramJson<TelegramUpdate[]>("getUpdates", {
    offset: -1,
    timeout: 0,
    allowed_updates: ["message", "callback_query"],
  });
  let offset = pending.reduce((maximum, update) => Math.max(maximum, update.update_id + 1), 0);

  while (true) {
    try {
      const updates = await telegramJson<TelegramUpdate[]>("getUpdates", {
        offset,
        timeout: 25,
        allowed_updates: ["message", "callback_query"],
      });
      for (const update of updates) {
        offset = Math.max(offset, update.update_id + 1);
        if (update.message) await handleMessage(update.message);
        if (update.callback_query) await handleCallback(update.callback_query);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "невідома помилка";
      console.error(`[owner-bot] polling error: ${shortText(message, 300)}`);
      await new Promise((resolve) => setTimeout(resolve, 5_000));
    }
  }
}

run()
  .catch((error) => {
    const message = error instanceof Error ? error.message : "невідома помилка";
    console.error(`[owner-bot] stopped: ${shortText(message, 300)}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
