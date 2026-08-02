import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { PrismaClient, ProductStatus } from "@prisma/client";
import {
  fetchMakerWorldModel,
  isAllowedMakerWorldImageUrl,
  MakerWorldFetchError,
  type MakerWorldModel,
} from "../src/lib/makerworld";

type TelegramUser = { id: number };
type TelegramChat = { id: number; type: string };
type TelegramMessage = {
  message_id: number;
  chat: TelegramChat;
  from?: TelegramUser;
  text?: string;
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
  albumSent: boolean;
};

type DownloadedImage = {
  fileName: string;
  urlPath: string;
  sourceIndex: number;
};

const prisma = new PrismaClient();
const sessions = new Map<string, DraftSession>();
const botToken = process.env.NARADADRUK_MAKERWORLD_TELEGRAM_BOT_TOKEN?.trim() || "";
const ownerChatIds = new Set(
  (process.env.NARADADRUK_MAKERWORLD_OWNER_CHAT_IDS || "")
    .split(/[\s,;]+/)
    .map((value) => value.trim())
    .filter(Boolean),
);
const postsChatId = process.env.NARADADRUK_POSTS_TELEGRAM_CHAT_ID?.trim() || "";
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

function positiveThreadId(value: string | undefined) {
  const parsed = Number(value || "");
  return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}

function postsThreadId() {
  return positiveThreadId(process.env.NARADADRUK_POSTS_TELEGRAM_THREAD_ID);
}

function publicProductUrl(slug: string) {
  const origin = new URL(
    process.env.NARADADRUK_PUBLIC_SITE_URL?.trim() || "https://studerria.com",
  );
  if (origin.protocol !== "https:" || origin.username || origin.password || origin.port) {
    throw new Error("NARADADRUK_PUBLIC_SITE_URL має бути публічним HTTPS URL без облікових даних.");
  }
  origin.pathname = "/";
  origin.search = "";
  origin.hash = "";
  const configuredBasePath = (process.env.NEXT_PUBLIC_BASE_PATH || "/naradadruk").trim();
  const basePath = configuredBasePath === "/" ? "" : `/${configuredBasePath.replace(/^\/+|\/+$/g, "")}`;
  return new URL(`${basePath}/product/${encodeURIComponent(slug)}`, origin).toString();
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
    `https://t.me/${encodeURIComponent(username)}`;
  const contactLink =
    normalizeTelegramLink(process.env.NARADADRUK_POSTS_TELEGRAM_CONTACT_URL || "") ||
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
  threadId?: number,
) {
  if (images.length === 0) return;
  const form = new FormData();
  form.set("chat_id", chatId);
  if (threadId) form.set("message_thread_id", String(threadId));

  if (images.length === 1) {
    const image = images[0];
    const buffer = await readFile(path.join(uploadDirectory(), image.fileName));
    form.set("photo", new Blob([new Uint8Array(buffer)], { type: mimeTypeForFile(image.fileName) }), image.fileName);
    form.set("caption", `🖥️ ${shortText(title, 900)}`);
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
      ...(index === 0 ? { caption: `🖥️ ${shortText(title, 900)}` } : {}),
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
    (await prisma.category.findUnique({ where: { slug: "3d-druk" } })) ||
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
            alt: `${model.title} — фото ${index + 1} із MakerWorld`,
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
      albumSent: false,
    };
    sessions.set(chatId, session);
    return session;
  } catch (error) {
    await deleteFiles(downloadedImages.map((image) => image.fileName));
    throw error;
  }
}

function selectedImages(session: DraftSession) {
  return session.images.filter((image) => image.selected);
}

function priceLabel(price: number | null) {
  return price == null ? "не вказано" : `${new Intl.NumberFormat("uk-UA").format(price)} грн`;
}

function telegramPostText(session: DraftSession, contactLink: string, channelLink: string) {
  return [
    `🖥️ <b>${escapeHtml(session.title)}</b>`,
    "🎨 Колір і розмір узгодимо перед друком.",
    `🛡️ ${escapeHtml(session.telegramSummary)}`,
    `💰 <b>${escapeHtml(priceLabel(session.price))}</b>`,
    "◾ Акуратний 3D-друк під ваше замовлення.",
    "",
    `📩 <a href="${escapeHtml(contactLink)}"><b>ЗАМОВИТИ</b></a>`,
    `✦ <a href="${escapeHtml(channelLink)}"><b>NARADA DRUK</b></a>`,
    `🔗 <a href="${escapeHtml(session.sourceUrl)}">Модель на MakerWorld</a>`,
  ].join("\n");
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

async function finalizeProduct(session: DraftSession) {
  const chosen = selectedImages(session);
  if (!session.price || session.price <= 0) throw new Error("Спочатку вкажіть ціну кнопкою «Ціна» або /price 450.");
  if (chosen.length === 0) throw new Error("Для публікації залиште хоча б одне зображення.");
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
        where: { productId: session.draftProductId, id: { notIn: chosenIds } },
      });
      await transaction.productImage.updateMany({
        where: { productId: session.draftProductId, id: { in: chosenIds } },
        data: {
          productId: existing.id,
          isCover: false,
          alt: `${session.title} — фото з MakerWorld`,
        },
      });
      await transaction.productImage.update({ where: { id: chosenIds[0] }, data: { isCover: true } });
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
      where: { productId: session.draftProductId, id: { notIn: chosenIds } },
    });
    await transaction.productImage.updateMany({
      where: { productId: session.draftProductId, id: { in: chosenIds } },
      data: { isCover: false, alt: `${session.title} — фото з MakerWorld` },
    });
    await transaction.productImage.update({ where: { id: chosenIds[0] }, data: { isCover: true } });
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
  if (!postsChatId) {
    throw new Error("Не налаштовано NARADADRUK_POSTS_TELEGRAM_CHAT_ID. Чернетка залишається неопублікованою.");
  }

  const { contactLink, channelLink } = await contactAndChannelLinks();
  publicProductUrl("configuration-check");

  if (!session.publishedProductId || !session.publishedSlug) {
    const product = await finalizeProduct(session);
    session.publishedProductId = product.id;
    session.publishedSlug = product.slug;
    session.draftProductId = product.id;
  }

  const chosen = selectedImages(session);
  let albumWarning = "";
  if (!session.albumSent) {
    try {
      await sendPhotoSet(postsChatId, chosen, session.title, postsThreadId());
      session.albumSent = true;
    } catch (error) {
      const message = error instanceof Error ? error.message : "невідома помилка";
      console.warn(`[makerworld-bot] destination album failed: ${shortText(message, 200)}`);
      albumWarning = "Telegram не прийняв альбом, але текстовий пост і товар опубліковані.";
    }
  }

  const productUrl = publicProductUrl(session.publishedSlug);
  await telegramJson("sendMessage", {
    chat_id: postsChatId,
    ...(postsThreadId() ? { message_thread_id: postsThreadId() } : {}),
    text: telegramPostText(session, contactLink, channelLink),
    parse_mode: "HTML",
    disable_web_page_preview: true,
    reply_markup: {
      inline_keyboard: [
        [{ text: "Замовити на сайті", url: productUrl }],
        [{ text: "Написати власнику", url: contactLink }],
      ],
    },
  });
  return { productUrl, albumWarning };
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
    "До фінального підтвердження товар має статус draft і не видимий покупцям.",
  ].join("\n");
}

function isAuthorizedPrivateChat(message: TelegramMessage) {
  return message.chat.type === "private" && ownerChatIds.has(String(message.chat.id));
}

function splitCommand(text: string) {
  const match = text.trim().match(/^\/([a-z_]+)(?:@[a-zA-Z0-9_]+)?(?:\s+([\s\S]*))?$/i);
  return match ? { command: match[1].toLowerCase(), argument: (match[2] || "").trim() } : null;
}

async function requestField(session: DraftSession, field: Exclude<AwaitingField, null>) {
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
  try {
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
      albumSent: false,
    });
    await sendMessage(chatId, `Не вдалося створити чернетку: ${escapeHtml(shortText(message, 500))}\n\nНадішліть інше публічне посилання або /cancel.`);
  }
}

async function handleMessage(message: TelegramMessage) {
  if (!isAuthorizedPrivateChat(message) || !message.text) return;
  const chatId = String(message.chat.id);
  const command = splitCommand(message.text);
  let session = sessions.get(chatId);

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
      albumSent: false,
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
      const { productUrl, albumWarning } = await publishProductPost(session);
      sessions.delete(chatId);
      await sendMessage(chatId, `Готово: товар активний, а пост опублікований.${albumWarning ? `\n${escapeHtml(albumWarning)}` : ""}\n<a href="${escapeHtml(productUrl)}">Відкрити сторінку товару</a>`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Не вдалося опублікувати товар.";
      await sendMessage(chatId, `${escapeHtml(shortText(message, 500))}\nЧернетку збережено. Виправте налаштування або дані й повторіть /publish.`, editorKeyboard());
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
  if (!message || !isAuthorizedPrivateChat(message)) {
    await answerCallback(callback.id, "Доступ заборонено.");
    return;
  }
  const chatId = String(message.chat.id);
  const session = sessions.get(chatId);
  if (!session || session.draftProductId <= 0) {
    await answerCallback(callback.id, "Активної чернетки немає.");
    return;
  }

  const action = callback.data?.replace(/^mw:/, "") || "";
  await answerCallback(callback.id);
  if (action === "preview") {
    await showPreview(session, true);
  } else if (action === "publish") {
    await handleMessage({ ...message, text: "/publish" });
  } else if (action === "cancel") {
    await handleMessage({ ...message, text: "/cancel" });
  } else if (["title", "description", "summary", "images", "price"].includes(action)) {
    await requestField(session, action as Exclude<AwaitingField, "url" | null>);
  }
}

async function configureCommands() {
  await telegramJson("setMyCommands", {
    commands: [
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
    scope: { type: "all_private_chats" },
  });
}

async function run() {
  if (!botToken || ownerChatIds.size === 0) {
    console.log("[makerworld-bot] disabled: bot token or owner chat allowlist is absent");
    return;
  }

  await configureCommands();
  console.log(`[makerworld-bot] started for ${ownerChatIds.size} allowed private chat(s)`);
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
      console.error(`[makerworld-bot] polling error: ${shortText(message, 300)}`);
      await new Promise((resolve) => setTimeout(resolve, 5_000));
    }
  }
}

run()
  .catch((error) => {
    const message = error instanceof Error ? error.message : "невідома помилка";
    console.error(`[makerworld-bot] stopped: ${shortText(message, 300)}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
