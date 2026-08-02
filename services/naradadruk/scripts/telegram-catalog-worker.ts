import { createHash } from "node:crypto";
import { mkdir, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import * as cheerio from "cheerio";
import {
  PrismaClient,
  ProductStatus,
  TelegramImportStatus,
} from "@prisma/client";
import {
  parseTelegramProductTemplate,
} from "../src/lib/telegram-product-template";

type TelegramPhoto = {
  url: string;
  linkedMessageUrl: string | null;
};

export type TelegramPost = {
  messageId: number;
  messageUrl: string;
  publishedAt: string | null;
  text: string;
  photos: TelegramPhoto[];
};

type ParsedTelegramPage = {
  posts: TelegramPost[];
  previousPath: string | null;
};

type DownloadedImage = {
  fileName: string;
  urlPath: string;
  alt: string;
  sortOrder: number;
  isCover: boolean;
};

const prisma = new PrismaClient();
const defaultChannel = "naradaprint";
const defaultIntervalMs = 5 * 60 * 1000;
const maxImageBytes = 8 * 1024 * 1024;
const userAgent =
  "Mozilla/5.0 (compatible; NaradaDrukCatalogBot/2.0; +https://t.me/naradaprint)";

function normalizeText(value: string) {
  return value
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function photoUrlFromStyle(style: string) {
  const match = style.match(/background-image:url\(['"]?([^'")]+)['"]?\)/i);
  return match?.[1] || null;
}

export function parseTelegramPage(html: string, channel: string): ParsedTelegramPage {
  const $ = cheerio.load(html);
  const posts: TelegramPost[] = [];

  $(".js-widget_message[data-post]").each((_index, element) => {
    const post = $(element);
    const postPath = post.attr("data-post") || "";
    const messageId = Number(postPath.split("/").at(-1));

    if (!Number.isInteger(messageId) || messageId <= 0) {
      return;
    }

    const textElement = post.find(".js-message_text").first();
    textElement.find("br").replaceWith("\n");
    const text = normalizeText(textElement.text());
    const publishedAt = post.find("time[datetime]").first().attr("datetime") || null;
    const messageUrl =
      post.find(".tgme_widget_message_date").first().attr("href") ||
      `https://t.me/${channel}/${messageId}`;
    const photos: TelegramPhoto[] = [];

    post.find(".js-message_photo").each((_photoIndex, photoElement) => {
      const photo = $(photoElement);
      const url = photoUrlFromStyle(photo.attr("style") || "");
      const linkedMessageUrl = photo.attr("href") || null;

      if (url && !photos.some((item) => item.url === url)) {
        photos.push({ url, linkedMessageUrl });
      }
    });

    posts.push({
      messageId,
      messageUrl,
      publishedAt,
      text,
      photos,
    });
  });

  return {
    posts,
    previousPath: $('link[rel="prev"]').attr("href") || null,
  };
}

async function fetchTelegramPage(url: string) {
  const response = await fetch(url, {
    headers: { "user-agent": userAgent },
    signal: AbortSignal.timeout(30_000),
  });

  if (!response.ok) {
    throw new Error(`Telegram повернув HTTP ${response.status}.`);
  }

  return response.text();
}

async function collectPosts(channel: string, lastSeenMessageId: number, fullScan: boolean) {
  const channelUrl = `https://t.me/s/${encodeURIComponent(channel)}`;
  const posts = new Map<number, TelegramPost>();
  const visited = new Set<string>();
  let nextUrl: string | null = channelUrl;

  while (nextUrl && !visited.has(nextUrl)) {
    visited.add(nextUrl);
    const page = parseTelegramPage(await fetchTelegramPage(nextUrl), channel);

    for (const post of page.posts) {
      posts.set(post.messageId, post);
    }

    const reachedPreviousCursor =
      !fullScan &&
      lastSeenMessageId > 0 &&
      page.posts.some((post) => post.messageId <= lastSeenMessageId);

    nextUrl =
      !reachedPreviousCursor && page.previousPath
        ? new URL(page.previousPath, channelUrl).toString()
        : null;
  }

  return {
    pages: visited.size,
    posts: [...posts.values()].sort((left, right) => left.messageId - right.messageId),
  };
}

function contentHash(post: TelegramPost) {
  return createHash("sha256")
    .update(post.text)
    .update("\n")
    .update(String(post.photos.length))
    .digest("hex");
}

function slugify(value: string) {
  const transliterationMap: Record<string, string> = {
    а: "a", б: "b", в: "v", г: "h", ґ: "g", д: "d", е: "e", є: "ye",
    ж: "zh", з: "z", и: "y", і: "i", ї: "yi", й: "i", к: "k", л: "l",
    м: "m", н: "n", о: "o", п: "p", р: "r", с: "s", т: "t", у: "u",
    ф: "f", х: "kh", ц: "ts", ч: "ch", ш: "sh", щ: "shch", ь: "",
    ю: "yu", я: "ya",
  };

  const normalized = value
    .trim()
    .toLocaleLowerCase("uk-UA")
    .split("")
    .map((character) => transliterationMap[character] ?? character)
    .join("")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");

  return normalized || "telegram-product";
}

async function generateUniqueSlug(title: string) {
  const base = slugify(title);
  let candidate = base;
  let attempt = 1;

  while (await prisma.product.findUnique({ where: { slug: candidate } })) {
    attempt += 1;
    candidate = `${base}-${attempt}`;
  }

  return candidate;
}

function extensionForContentType(contentType: string) {
  if (contentType.includes("image/avif")) return "avif";
  if (contentType.includes("image/gif")) return "gif";
  if (contentType.includes("image/png")) return "png";
  if (contentType.includes("image/webp")) return "webp";
  return "jpg";
}

function resolveUploadDirectory() {
  const configured = process.env.UPLOAD_DIR || "./uploads";
  return path.isAbsolute(configured) ? configured : path.resolve(process.cwd(), configured);
}

async function downloadImages(post: TelegramPost, title: string) {
  const uploadDirectory = resolveUploadDirectory();
  const downloaded: DownloadedImage[] = [];
  await mkdir(uploadDirectory, { recursive: true });

  try {
    for (const [index, photo] of post.photos.entries()) {
      const response = await fetch(photo.url, {
        headers: { "user-agent": userAgent },
        signal: AbortSignal.timeout(30_000),
      });

      if (!response.ok) {
        throw new Error(`Не вдалося завантажити фото ${index + 1}: HTTP ${response.status}.`);
      }

      const contentType = response.headers.get("content-type") || "";

      if (!contentType.toLocaleLowerCase().startsWith("image/")) {
        throw new Error(`Telegram повернув некоректний формат фото ${index + 1}.`);
      }

      const buffer = Buffer.from(await response.arrayBuffer());

      if (buffer.byteLength > maxImageBytes) {
        throw new Error(`Фото ${index + 1} перевищує 8 MB.`);
      }

      const extension = extensionForContentType(contentType);
      const fileName = `telegram-${post.messageId}-${index + 1}-${Date.now()}.${extension}`;
      await writeFile(path.join(uploadDirectory, fileName), buffer);
      downloaded.push({
        fileName,
        urlPath: `/uploads/${fileName}`,
        alt: `${title} — фото ${index + 1}`,
        sortOrder: (index + 1) * 10,
        isCover: index === 0,
      });
    }
  } catch (error) {
    await deleteDownloadedImages(downloaded);
    throw error;
  }

  return downloaded;
}

async function deleteDownloadedImages(images: DownloadedImage[]) {
  await Promise.all(
    images.map((image) =>
      unlink(path.join(resolveUploadDirectory(), image.fileName)).catch(() => undefined),
    ),
  );
}

async function resolveCategory(categoryValue: string) {
  const categories = await prisma.category.findMany({ where: { isVisible: true } });
  const normalized = categoryValue.trim().toLocaleLowerCase("uk-UA");
  const slug = slugify(categoryValue);

  return categories.find(
    (category) =>
      category.slug.toLocaleLowerCase("uk-UA") === normalized ||
      category.slug === slug ||
      category.name.trim().toLocaleLowerCase("uk-UA") === normalized,
  );
}

function shortDescription(description: string) {
  const firstParagraph = description.split(/\n\s*\n/)[0].replace(/\s+/g, " ").trim();
  return firstParagraph.length <= 180
    ? firstParagraph
    : `${firstParagraph.slice(0, 177).trimEnd()}…`;
}

async function saveFailedImport(
  channel: string,
  post: TelegramPost,
  hash: string,
  error: string,
  title = "",
) {
  await prisma.telegramPostImport.upsert({
    where: {
      channel_messageId: {
        channel,
        messageId: post.messageId,
      },
    },
    update: {
      messageUrl: post.messageUrl,
      contentHash: hash,
      title,
      status: TelegramImportStatus.failed,
      error,
    },
    create: {
      channel,
      messageId: post.messageId,
      messageUrl: post.messageUrl,
      contentHash: hash,
      title,
      status: TelegramImportStatus.failed,
      error,
    },
  });
}

async function importTemplatePost(channel: string, post: TelegramPost) {
  const parsed = parseTelegramProductTemplate(post.text);

  if (!parsed.matched) {
    return "ignored" as const;
  }

  const hash = contentHash(post);
  const previousAttempt = await prisma.telegramPostImport.findUnique({
    where: {
      channel_messageId: {
        channel,
        messageId: post.messageId,
      },
    },
  });

  if (previousAttempt?.status === TelegramImportStatus.imported) {
    return "already-imported" as const;
  }

  if (
    previousAttempt?.status === TelegramImportStatus.failed &&
    previousAttempt.contentHash === hash
  ) {
    return "unchanged-failure" as const;
  }

  if (!parsed.ok) {
    await saveFailedImport(channel, post, hash, parsed.errors.join(" "));
    return "failed" as const;
  }

  const product = parsed.product;
  const category = await resolveCategory(product.category);

  if (!category) {
    await saveFailedImport(
      channel,
      post,
      hash,
      `Категорію «${product.category}» не знайдено. Використайте назву категорії з адмінки.`,
      product.title,
    );
    return "failed" as const;
  }

  if (post.photos.length === 0) {
    await saveFailedImport(
      channel,
      post,
      hash,
      "Додайте до Telegram-допису хоча б одне фото.",
      product.title,
    );
    return "failed" as const;
  }

  const images = await downloadImages(post, product.title);

  try {
    const slug = await generateUniqueSlug(product.title);
    const shouldPublish = product.shouldPublish && images.length > 0;
    const saved = await prisma.$transaction(async (transaction) => {
      const createdProduct = await transaction.product.create({
        data: {
          title: product.title,
          slug,
          categoryId: category.id,
          shortDescription: shortDescription(product.description),
          fullDescription: product.description,
          status: shouldPublish ? ProductStatus.published : ProductStatus.draft,
          basePrice: product.basePrice,
          priceFrom: product.priceFrom,
          leadTime: product.leadTime,
          materialNote: product.material,
          deliveryNote: product.delivery,
          paymentNote: product.payment,
          sourceTelegramChannel: channel,
          sourceTelegramMessageId: post.messageId,
          sourceTelegramUrl: post.messageUrl,
          sourceTelegramPublishedAt: post.publishedAt ? new Date(post.publishedAt) : null,
          variants: {
            create: product.variants.map((variant, index) => ({
              label: variant.label,
              price: variant.price,
              description: variant.priceFrom ? "Ціна від вказаної суми." : "",
              sortOrder: (index + 1) * 10,
            })),
          },
          images: {
            create: images,
          },
        },
      });

      await transaction.telegramPostImport.upsert({
        where: {
          channel_messageId: {
            channel,
            messageId: post.messageId,
          },
        },
        update: {
          messageUrl: post.messageUrl,
          contentHash: hash,
          title: product.title,
          status: TelegramImportStatus.imported,
          error: "",
          productId: createdProduct.id,
        },
        create: {
          channel,
          messageId: post.messageId,
          messageUrl: post.messageUrl,
          contentHash: hash,
          title: product.title,
          status: TelegramImportStatus.imported,
          productId: createdProduct.id,
        },
      });

      return createdProduct;
    });

    console.log(
      `[telegram-sync] imported ${channel}/${post.messageId} as ${saved.status} product ${saved.id}`,
    );
    return "imported" as const;
  } catch (error) {
    await deleteDownloadedImages(images);
    const message = error instanceof Error ? error.message : "Невідома помилка імпорту.";
    await saveFailedImport(channel, post, hash, message, product.title);
    throw error;
  }
}

function pollIntervalMs() {
  const parsed = Number(process.env.TELEGRAM_POLL_INTERVAL_MS || defaultIntervalMs);
  return Number.isFinite(parsed) && parsed >= 60_000 ? Math.round(parsed) : defaultIntervalMs;
}

function channelName() {
  return (process.env.TELEGRAM_CHANNEL_USERNAME || defaultChannel)
    .trim()
    .replace(/^@/, "");
}

export async function syncTelegramChannel(options?: { fullScan?: boolean }) {
  const channel = channelName();
  const syncState = await prisma.telegramChannelSync.findUnique({ where: { channel } });
  const fullScan = options?.fullScan === true || !syncState;
  const collected = await collectPosts(
    channel,
    syncState?.lastSeenMessageId ?? 0,
    fullScan,
  );
  let imported = 0;

  for (const post of collected.posts) {
    const result = await importTemplatePost(channel, post);

    if (result === "imported") {
      imported += 1;
    }
  }

  const maximumMessageId = collected.posts.reduce(
    (maximum, post) => Math.max(maximum, post.messageId),
    syncState?.lastSeenMessageId ?? 0,
  );
  const now = new Date();

  await prisma.telegramChannelSync.upsert({
    where: { channel },
    update: {
      lastSeenMessageId: maximumMessageId,
      lastCheckedAt: now,
      lastSuccessfulAt: now,
      lastError: "",
      importedCount: { increment: imported },
    },
    create: {
      channel,
      lastSeenMessageId: maximumMessageId,
      lastCheckedAt: now,
      lastSuccessfulAt: now,
      importedCount: imported,
    },
  });

  console.log(
    `[telegram-sync] checked ${collected.posts.length} posts across ${collected.pages} page(s); imported ${imported}`,
  );

  return { ...collected, imported };
}

async function recordSyncError(error: unknown) {
  const channel = channelName();
  const message = error instanceof Error ? error.message : "Невідома помилка синхронізації.";

  await prisma.telegramChannelSync.upsert({
    where: { channel },
    update: {
      lastCheckedAt: new Date(),
      lastError: message.slice(0, 1000),
    },
    create: {
      channel,
      lastCheckedAt: new Date(),
      lastError: message.slice(0, 1000),
    },
  });

  console.error(`[telegram-sync] ${message}`);
}

async function run() {
  const once = process.argv.includes("--once");
  const fullScan = process.argv.includes("--full");

  do {
    try {
      await syncTelegramChannel({ fullScan });
    } catch (error) {
      await recordSyncError(error);

      if (once) {
        process.exitCode = 1;
      }
    }

    if (once) {
      break;
    }

    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs()));
  } while (true);
}

run()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
