import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const catalogDirectory = path.resolve(process.cwd(), "catalog");
const sourcePath = path.join(catalogDirectory, "telegram-posts.json");
const jsonOutputPath = path.join(catalogDirectory, "products.json");
const csvOutputPath = path.join(catalogDirectory, "products.csv");

const categories = [
  {
    name: "3D друк",
    slug: "3d-druk",
    description: "Функціональні вироби, підставки, органайзери та аксесуари.",
    sortOrder: 10,
  },
  {
    name: "Страйкбол",
    slug: "strajkbol",
    description: "Аксесуари, кріплення та комплектуючі для спорядження.",
    sortOrder: 20,
  },
  {
    name: "Декор",
    slug: "dekor",
    description: "Тематичні вироби для столу, полиці та робочого простору.",
    sortOrder: 30,
  },
];

const productDefinitions = [
  { postId: 6, title: "Перенос вогню / упор 45°", slug: "perenos-vogniu-upor-45", categorySlug: "strajkbol", basePrice: 360 },
  { postId: 9, title: "Страйкбольний ніж", slug: "strajkbolnyi-nizh", categorySlug: "strajkbol", basePrice: 265 },
  { postId: 16, title: "Полум’ягасник 14 мм", slug: "polumiagasnyk-14-mm", categorySlug: "strajkbol", basePrice: 145 },
  { postId: 19, title: "Захист прицілу 30 мм", slug: "zakhyst-prytsilu-30-mm", categorySlug: "strajkbol", basePrice: 60 },
  { postId: 22, title: "Кріплення-кобура для AR", slug: "kriplennia-kobura-ar", categorySlug: "strajkbol", basePrice: 230 },
  {
    postId: 25,
    title: "Настінне кріплення для привода",
    slug: "nastinne-kriplennia-pryvoda",
    categorySlug: "strajkbol",
    basePrice: 350,
    priceFrom: true,
  },
  { postId: 29, title: "Speedloader для GBB Glock", slug: "speedloader-gbb-glock", categorySlug: "strajkbol", basePrice: 50 },
  { postId: 33, title: "Підставка під 6 магазинів AR/M", slug: "pidstavka-6-magazyniv-ar-m", categorySlug: "strajkbol", basePrice: 410 },
  { postId: 36, title: "Швидкознімний упор M-LOK", slug: "shvydkoznimnyi-upor-m-lok", categorySlug: "strajkbol", basePrice: 170 },
  {
    postId: 40,
    title: "Тактична рукоятка",
    slug: "taktychna-rukoiatka",
    categorySlug: "strajkbol",
    variants: [
      { label: "M-LOK із болтами", price: 255 },
      { label: "Picatinny без болтів", price: 230 },
    ],
  },
  { postId: 44, title: "Кришка бункерного магазина АК", slug: "kryshka-bunkernogo-magazyna-ak", categorySlug: "strajkbol", basePrice: 30 },
  { postId: 47, title: "Двоколірний настільний органайзер", slug: "dvokolirnyi-nastilnyi-organaizer", categorySlug: "3d-druk", basePrice: 335 },
  { postId: 50, title: "Муляж гранати M67", slug: "muliazh-granaty-m67", categorySlug: "strajkbol", basePrice: 275 },
  { postId: 52, title: "Підставка під Glock 17 Gen 4/5", slug: "pidstavka-glock-17", categorySlug: "strajkbol", basePrice: 220 },
  { postId: 55, title: "Кріплення GoPro на шолом FAST", slug: "kriplennia-gopro-fast", categorySlug: "strajkbol", basePrice: 110 },
  { postId: 58, title: "П’ятка магазина Glock GBB", slug: "piatka-magazyna-glock-gbb", categorySlug: "strajkbol", basePrice: 75 },
  { postId: 61, title: "Підставка під CZ 75", slug: "pidstavka-cz-75", categorySlug: "strajkbol", basePrice: 240 },
  {
    postId: 64,
    title: "Аксесуари для IKEA SKÅDIS",
    slug: "aksesuary-ikea-skadis",
    categorySlug: "3d-druk",
    variants: [
      { label: "Ваза", price: 300 },
      { label: "Підставка під клавіатуру", price: 35 },
      { label: "Підставка під навушники", price: 85 },
      { label: "Підставка під павербанк", price: 180 },
      { label: "Підставка під колонку", price: 30 },
      { label: "Підставка під термометр", price: 35 },
      { label: "Підставка під геймпад", price: 230 },
    ],
  },
  { postId: 71, title: "Глушник PBS-1 для АК/AR", slug: "glushnyk-pbs-1-ak-ar", categorySlug: "strajkbol", basePrice: 325 },
  { postId: 73, title: "Кріплення GoPro Gen II", slug: "kriplennia-gopro-gen-2", categorySlug: "strajkbol", basePrice: 155 },
  { postId: 76, title: "RIS-планка M-LOK — Picatinny", slug: "ris-planka-m-lok-picatinny", categorySlug: "strajkbol", basePrice: 90 },
  { postId: 78, title: "Райзер під коліматор", slug: "raizer-pid-kolimator", categorySlug: "strajkbol", basePrice: 250 },
  { postId: 82, title: "Стенд для HyperX QuadCast", slug: "stend-hyperx-quadcast", categorySlug: "3d-druk", basePrice: 380 },
  {
    postId: 85,
    title: "Підставка під відеокарту",
    slug: "pidstavka-pid-videokartu",
    categorySlug: "3d-druk",
    variants: [
      { label: "Менша", price: 60 },
      { label: "Більша", price: 80 },
    ],
  },
  {
    postId: 87,
    title: "Колекція Formula 1",
    slug: "kolektsiia-formula-1",
    categorySlug: "dekor",
    variants: [
      { label: "Календар Гран-прі 2026", price: 600 },
      { label: "Гоночний трек", price: 200 },
      { label: "Підставка LEGO Speed Champions", price: 120 },
    ],
  },
];

function stripDecoration(value) {
  return value
    .replace(/^[^\p{L}\p{N}]+/u, "")
    .replace(/\s+/g, " ")
    .trim();
}

function descriptionLines(post) {
  const lines = post.text
    .split("\n")
    .map(stripDecoration)
    .filter(Boolean);

  return lines.filter((line, index) => {
    if (index === 0) return false;
    if (/^(замовити|narada druk|нарада друк)$/iu.test(line)) return false;
    if (/\b\d+\s*грн\b/iu.test(line)) return false;
    return true;
  });
}

function buildProduct(definition, post, sortOrder) {
  const lines = descriptionLines(post);
  const variants = (definition.variants || []).map((variant, index) => ({
    ...variant,
    description: "",
    sortOrder: (index + 1) * 10,
  }));

  return {
    externalId: `telegram-${post.messageId}`,
    title: definition.title,
    slug: definition.slug,
    categorySlug: definition.categorySlug,
    shortDescription: lines[0] || "3D-друкований виріб із каталогу Narada Druk.",
    fullDescription: lines.join("\n"),
    status: "published",
    isFeatured: false,
    basePrice: definition.basePrice ?? null,
    priceFrom: definition.priceFrom ?? false,
    leadTime: "",
    materialNote: "",
    deliveryNote: "",
    paymentNote: "",
    sortOrder,
    variants,
    images: post.photos.map((photo, index) => ({
      localPath: photo.localPath,
      sourceUrl: photo.url,
      sourceMessageUrl: photo.linkedMessageUrl,
      alt: `${definition.title} — фото ${index + 1}`,
      sortOrder: (index + 1) * 10,
      isCover: index === 0,
    })),
    source: {
      channel: "naradaprint",
      messageId: post.messageId,
      messageUrl: post.messageUrl,
      publishedAt: post.publishedAt,
      originalText: post.text,
    },
  };
}

function csvCell(value) {
  const text = String(value ?? "");
  return `"${text.replaceAll('"', '""')}"`;
}

function buildCsv(products) {
  const rows = [
    [
      "externalId",
      "title",
      "slug",
      "categorySlug",
      "basePrice",
      "priceFrom",
      "variants",
      "shortDescription",
      "imagePaths",
      "telegramUrl",
    ],
    ...products.map((product) => [
      product.externalId,
      product.title,
      product.slug,
      product.categorySlug,
      product.basePrice,
      product.priceFrom,
      product.variants.map((variant) => `${variant.label}: ${variant.price}`).join(" | "),
      product.shortDescription,
      product.images.map((image) => image.localPath).join(" | "),
      product.source.messageUrl,
    ]),
  ];

  return `\uFEFF${rows.map((row) => row.map(csvCell).join(";")).join("\n")}\n`;
}

async function main() {
  const source = JSON.parse(await readFile(sourcePath, "utf8"));
  const postsById = new Map(source.posts.map((post) => [post.messageId, post]));
  const productPostIds = source.posts
    .filter((post) => /\b\d+\s*грн\b/iu.test(post.text))
    .map((post) => post.messageId);
  const definedPostIds = productDefinitions.map((product) => product.postId);
  const missingDefinitions = productPostIds.filter((postId) => !definedPostIds.includes(postId));
  const missingPosts = definedPostIds.filter((postId) => !postsById.has(postId));

  if (missingDefinitions.length || missingPosts.length) {
    throw new Error(
      `Catalog mapping is incomplete. Unmapped product posts: ${missingDefinitions.join(", ") || "none"}; missing source posts: ${missingPosts.join(", ") || "none"}.`,
    );
  }

  const products = productDefinitions.map((definition, index) =>
    buildProduct(definition, postsById.get(definition.postId), (index + 1) * 10),
  );
  const payload = {
    schemaVersion: 1,
    generatedAt: source.source.scrapedAt,
    source: source.source,
    stats: {
      categories: categories.length,
      products: products.length,
      variants: products.reduce((total, product) => total + product.variants.length, 0),
      images: products.reduce((total, product) => total + product.images.length, 0),
    },
    categories,
    products,
  };

  await writeFile(jsonOutputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  await writeFile(csvOutputPath, buildCsv(products), "utf8");
  console.log(
    `Built ${payload.stats.products} products, ${payload.stats.variants} variants and ${payload.stats.images} images.`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
