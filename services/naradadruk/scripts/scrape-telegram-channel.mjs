import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import * as cheerio from "cheerio";

const channel = process.argv[2] || "naradaprint";
const outputPath = path.resolve(
  process.cwd(),
  process.argv[3] || "catalog/telegram-posts.json",
);
const shouldDownloadImages = process.argv.includes("--download-images");
const imageDirectory = path.join(path.dirname(outputPath), "images", "telegram");
const channelUrl = `https://t.me/s/${encodeURIComponent(channel)}`;

function normalizeText(value) {
  return value
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function photoUrlFromStyle(style) {
  const match = style.match(/background-image:url\(['"]?([^'")]+)['"]?\)/i);
  return match?.[1] || null;
}

function parsePage(html) {
  const $ = cheerio.load(html);
  const posts = [];

  $(".js-widget_message[data-post]").each((_index, element) => {
    const post = $(element);
    const postPath = post.attr("data-post") || "";
    const messageId = Number(postPath.split("/").at(-1));

    if (!Number.isInteger(messageId)) {
      return;
    }

    const textElement = post.find(".js-message_text").first();
    textElement.find("br").replaceWith("\n");
    const text = normalizeText(textElement.text());
    const dateTime = post.find("time[datetime]").first().attr("datetime") || null;
    const messageUrl =
      post.find(".tgme_widget_message_date").first().attr("href") ||
      `https://t.me/${channel}/${messageId}`;

    const photos = [];
    post.find(".js-message_photo").each((_photoIndex, photoElement) => {
      const photo = $(photoElement);
      const url = photoUrlFromStyle(photo.attr("style") || "");
      const linkedMessageUrl = photo.attr("href") || null;

      if (url && !photos.some((item) => item.url === url)) {
        photos.push({ url, linkedMessageUrl });
      }
    });

    const links = [];
    textElement.find("a[href]").each((_linkIndex, linkElement) => {
      const link = $(linkElement);
      const href = link.attr("href");

      if (href && !links.some((item) => item.url === href)) {
        links.push({
          label: normalizeText(link.text()),
          url: href,
        });
      }
    });

    posts.push({
      messageId,
      messageUrl,
      publishedAt: dateTime,
      text,
      photos,
      links,
    });
  });

  const previousPath = $('link[rel="prev"]').attr("href") || null;
  return { posts, previousPath };
}

async function fetchPage(url) {
  const response = await fetch(url, {
    headers: {
      "user-agent":
        "Mozilla/5.0 (compatible; NaradaDrukCatalogBot/1.0; +https://t.me/naradaprint)",
    },
  });

  if (!response.ok) {
    throw new Error(`Telegram returned ${response.status} for ${url}`);
  }

  return response.text();
}

function extensionForContentType(contentType) {
  if (contentType.includes("image/png")) return "png";
  if (contentType.includes("image/webp")) return "webp";
  if (contentType.includes("image/gif")) return "gif";
  return "jpg";
}

async function downloadPhotos(posts) {
  await mkdir(imageDirectory, { recursive: true });

  for (const post of posts) {
    for (const [index, photo] of post.photos.entries()) {
      const response = await fetch(photo.url);

      if (!response.ok) {
        throw new Error(`Image download returned ${response.status} for ${photo.url}`);
      }

      const extension = extensionForContentType(response.headers.get("content-type") || "");
      const fileName = `${post.messageId}-${String(index + 1).padStart(2, "0")}.${extension}`;
      const filePath = path.join(imageDirectory, fileName);
      const relativePath = path.relative(path.dirname(outputPath), filePath).replaceAll("\\", "/");

      await writeFile(filePath, Buffer.from(await response.arrayBuffer()));
      photo.localPath = relativePath;
    }
  }
}

async function main() {
  const collected = new Map();
  const visited = new Set();
  let nextUrl = channelUrl;

  while (nextUrl && !visited.has(nextUrl)) {
    visited.add(nextUrl);
    const html = await fetchPage(nextUrl);
    const { posts, previousPath } = parsePage(html);

    for (const post of posts) {
      collected.set(post.messageId, post);
    }

    nextUrl = previousPath ? new URL(previousPath, channelUrl).toString() : null;
  }

  const posts = [...collected.values()].sort((left, right) => left.messageId - right.messageId);

  if (shouldDownloadImages) {
    await downloadPhotos(posts);
  }

  const payload = {
    schemaVersion: 1,
    source: {
      type: "telegram-public-channel",
      channel,
      url: `https://t.me/${channel}`,
      scrapedAt: new Date().toISOString(),
    },
    stats: {
      pages: visited.size,
      posts: posts.length,
      photos: posts.reduce((total, post) => total + post.photos.length, 0),
    },
    posts,
  };

  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  console.log(
    `Saved ${payload.stats.posts} posts and ${payload.stats.photos} photos from ${visited.size} pages to ${outputPath}`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
