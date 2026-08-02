import * as cheerio from "cheerio";

const makerWorldHosts = new Set(["makerworld.com", "www.makerworld.com"]);
const makerWorldImageHostSuffixes = [
  "makerworld.com",
  "bambulab.com",
  "bambulab.cn",
  "bblcdn.com",
  "bblmw.com",
];
const maxPageBytes = 2 * 1024 * 1024;
const maxImageCandidates = 24;
const userAgent =
  "Mozilla/5.0 (compatible; NaradaDrukMakerWorldBot/1.0; +https://t.me/naradaprint)";

export type MakerWorldModel = {
  sourceUrl: string;
  title: string;
  description: string;
  summary: string;
  author: string;
  metadata: string[];
  imageUrls: string[];
};

export class MakerWorldFetchError extends Error {}

function cleanText(value: unknown, maximumLength: number) {
  return String(value ?? "")
    .replace(/<[^>]*>/g, " ")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim()
    .slice(0, maximumLength);
}

function isAllowedMakerWorldHost(hostname: string) {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  return makerWorldHosts.has(normalized) || normalized.endsWith(".makerworld.com");
}

export function parseMakerWorldUrl(value: string) {
  let url: URL;

  try {
    url = new URL(value.trim());
  } catch {
    throw new MakerWorldFetchError("Надішліть повне публічне посилання MakerWorld.");
  }

  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.port ||
    !isAllowedMakerWorldHost(url.hostname) ||
    !/\/models\/\d+/i.test(url.pathname)
  ) {
    throw new MakerWorldFetchError(
      "Потрібне публічне HTTPS-посилання на модель із домену makerworld.com.",
    );
  }

  url.hash = "";
  url.search = "";
  return url;
}

function isAllowedImageHost(hostname: string) {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  return makerWorldImageHostSuffixes.some(
    (suffix) => normalized === suffix || normalized.endsWith(`.${suffix}`),
  );
}

function normalizeImageUrl(value: unknown, baseUrl: URL) {
  const raw = String(value ?? "")
    .replace(/\\u002[fF]/g, "/")
    .replace(/\\u003[aA]/g, ":")
    .replace(/\\\//g, "/")
    .replace(/&amp;/g, "&")
    .trim();

  if (!raw || raw.startsWith("data:") || raw.startsWith("blob:")) {
    return null;
  }

  try {
    const url = new URL(raw, baseUrl);
    if (url.protocol !== "https:" || url.username || url.password || url.port) return null;
    if (!isAllowedImageHost(url.hostname)) return null;
    return url.toString();
  } catch {
    return null;
  }
}

async function readResponseWithLimit(response: Response, maximumBytes: number) {
  const contentLength = Number(response.headers.get("content-length") || "0");
  if (contentLength > maximumBytes) {
    throw new MakerWorldFetchError("Сторінка MakerWorld завелика для безпечного оброблення.");
  }

  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel();
      throw new MakerWorldFetchError("Сторінка MakerWorld завелика для безпечного оброблення.");
    }
    chunks.push(value);
  }

  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
}

async function fetchPublicHtml(initialUrl: URL) {
  let currentUrl = initialUrl;

  for (let redirect = 0; redirect <= 3; redirect += 1) {
    const response = await fetch(currentUrl, {
      redirect: "manual",
      headers: {
        accept: "text/html,application/xhtml+xml",
        "user-agent": userAgent,
      },
      signal: AbortSignal.timeout(20_000),
    });

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location || redirect === 3) {
        throw new MakerWorldFetchError("MakerWorld повернув забагато перенаправлень.");
      }
      const nextUrl = new URL(location, currentUrl);
      if (
        nextUrl.protocol !== "https:" ||
        nextUrl.username ||
        nextUrl.password ||
        nextUrl.port ||
        !isAllowedMakerWorldHost(nextUrl.hostname)
      ) {
        throw new MakerWorldFetchError("MakerWorld перенаправив на непідтримуваний домен.");
      }
      currentUrl = nextUrl;
      continue;
    }

    if (!response.ok) {
      throw new MakerWorldFetchError(`MakerWorld повернув HTTP ${response.status}.`);
    }

    const contentType = response.headers.get("content-type")?.toLowerCase() || "";
    if (!contentType.includes("text/html")) {
      throw new MakerWorldFetchError("MakerWorld повернув сторінку в непідтримуваному форматі.");
    }

    return {
      html: await readResponseWithLimit(response, maxPageBytes),
      finalUrl: currentUrl,
    };
  }

  throw new MakerWorldFetchError("Не вдалося відкрити сторінку MakerWorld.");
}

function collectJsonLd(value: unknown, result: {
  names: string[];
  descriptions: string[];
  authors: string[];
  images: unknown[];
  metadata: string[];
}, depth = 0) {
  if (depth > 12) return;
  if (Array.isArray(value)) {
    value.forEach((item) => collectJsonLd(item, result, depth + 1));
    return;
  }

  if (!value || typeof value !== "object") return;
  const record = value as Record<string, unknown>;

  if (typeof record.name === "string") result.names.push(record.name);
  if (typeof record.headline === "string") result.names.push(record.headline);
  if (typeof record.description === "string") result.descriptions.push(record.description);
  if (record.image) result.images.push(record.image);

  if (typeof record.author === "string") {
    result.authors.push(record.author);
  } else if (record.author && typeof record.author === "object") {
    const author = record.author as Record<string, unknown>;
    if (typeof author.name === "string") result.authors.push(author.name);
  }

  for (const key of ["material", "category", "keywords", "license"]) {
    const raw = record[key];
    if (typeof raw === "string") result.metadata.push(raw);
    if (Array.isArray(raw)) result.metadata.push(raw.join(", "));
  }

  for (const nested of Object.values(record)) {
    if (nested && typeof nested === "object") collectJsonLd(nested, result, depth + 1);
  }
}

function flattenImages(value: unknown, depth = 0): unknown[] {
  if (depth > 6) return [];
  if (Array.isArray(value)) return value.flatMap((item) => flattenImages(item, depth + 1));
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return [record.url, record.contentUrl, record.thumbnailUrl].flatMap((item) => flattenImages(item, depth + 1));
  }
  return [value];
}

function firstSentence(value: string) {
  const normalized = cleanText(value, 1000);
  const sentence = normalized.match(/^[\s\S]{1,220}?(?:[.!?](?=\s|$)|$)/)?.[0] || normalized.slice(0, 220);
  return sentence.trim() || "Практична модель для якісного 3D-друку під замовлення.";
}

export async function fetchMakerWorldModel(value: string): Promise<MakerWorldModel> {
  const requestedUrl = parseMakerWorldUrl(value);
  const { html, finalUrl } = await fetchPublicHtml(requestedUrl);
  const $ = cheerio.load(html);
  const jsonLd = {
    names: [] as string[],
    descriptions: [] as string[],
    authors: [] as string[],
    images: [] as unknown[],
    metadata: [] as string[],
  };

  $('script[type="application/ld+json"]').each((_index, element) => {
    try {
      collectJsonLd(JSON.parse($(element).text()), jsonLd);
    } catch {
      // Ignore malformed public metadata and continue with Open Graph data.
    }
  });

  const meta = (selector: string) => cleanText($(selector).first().attr("content"), 6000);
  const rawTitle =
    meta('meta[property="og:title"]') ||
    meta('meta[name="twitter:title"]') ||
    cleanText(jsonLd.names[0], 300) ||
    cleanText($("title").first().text(), 300);
  const title = cleanText(
    rawTitle.replace(/\s*[-|–—]\s*MakerWorld.*$/i, ""),
    140,
  );
  const description = [
    meta('meta[property="og:description"]'),
    meta('meta[name="description"]'),
    ...jsonLd.descriptions,
  ]
    .map((item) => cleanText(item, 6000))
    .filter(Boolean)
    .sort((left, right) => right.length - left.length)[0] ||
    "Модель із MakerWorld для друку під замовлення.";

  if (!title) {
    throw new MakerWorldFetchError(
      "На публічній сторінці не знайдено назву моделі. Перевірте посилання або доступність сторінки.",
    );
  }

  const candidates: unknown[] = [];
  $('meta[property="og:image"], meta[property="og:image:url"], meta[name="twitter:image"], meta[name="twitter:image:src"]').each(
    (_index, element) => candidates.push($(element).attr("content")),
  );
  candidates.push(...jsonLd.images.flatMap((image) => flattenImages(image)));
  $("img").each((_index, element) => {
    const image = $(element);
    const width = Number(image.attr("width") || "0");
    const height = Number(image.attr("height") || "0");
    if ((width === 0 && height === 0) || width >= 300 || height >= 300) {
      candidates.push(image.attr("src"), image.attr("data-src"), image.attr("data-original"));
    }
  });
  $("source[srcset], img[srcset]").each((_index, element) => {
    for (const entry of String($(element).attr("srcset") || "").split(",")) {
      candidates.push(entry.trim().split(/\s+/)[0]);
    }
  });

  const decodedHtml = html
    .replace(/\\u002[fF]/g, "/")
    .replace(/\\u003[aA]/g, ":")
    .replace(/\\\//g, "/");
  candidates.push(
    ...(decodedHtml.match(/https:\/\/[^\s"'<>\\]+?\.(?:jpe?g|png|webp|avif)(?:\?[^\s"'<>\\]*)?/gi) || []),
  );

  const imageUrls: string[] = [];
  const imageKeys = new Set<string>();
  for (const candidate of candidates) {
    const normalized = normalizeImageUrl(candidate, finalUrl);
    if (!normalized) continue;
    const normalizedUrl = new URL(normalized);
    const imageKey = `${normalizedUrl.origin}${normalizedUrl.pathname}`.toLowerCase();
    if (imageKeys.has(imageKey)) continue;
    if (/\b(?:avatar|logo|icon|emoji)\b/i.test(normalizedUrl.pathname)) continue;
    imageKeys.add(imageKey);
    imageUrls.push(normalized);
    if (imageUrls.length >= maxImageCandidates) break;
  }

  const author = cleanText(
    jsonLd.authors[0] || meta('meta[name="author"]'),
    120,
  );
  const metadata = [
    ...jsonLd.metadata,
    meta('meta[name="keywords"]'),
  ]
    .map((item) => cleanText(item, 240))
    .filter((item, index, values) => item && values.indexOf(item) === index)
    .slice(0, 6);

  const sourceUrl = new URL(finalUrl);
  sourceUrl.hash = "";
  sourceUrl.search = "";

  return {
    sourceUrl: sourceUrl.toString(),
    title,
    description,
    summary: firstSentence(description),
    author,
    metadata,
    imageUrls,
  };
}

export function isAllowedMakerWorldImageUrl(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password && !url.port && isAllowedImageHost(url.hostname);
  } catch {
    return false;
  }
}
