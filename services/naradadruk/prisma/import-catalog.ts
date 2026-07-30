import { copyFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PrismaClient, ProductStatus } from "@prisma/client";

type CatalogCategory = {
  name: string;
  slug: string;
  description: string;
  sortOrder: number;
};

type CatalogProduct = {
  title: string;
  slug: string;
  categorySlug: string;
  shortDescription: string;
  fullDescription: string;
  status: "draft" | "published";
  isFeatured: boolean;
  basePrice: number | null;
  priceFrom: boolean;
  leadTime: string;
  materialNote: string;
  deliveryNote: string;
  paymentNote: string;
  sortOrder: number;
  variants: Array<{
    label: string;
    price: number;
    description: string;
    sortOrder: number;
  }>;
  images: Array<{
    localPath: string;
    alt: string;
    sortOrder: number;
    isCover: boolean;
  }>;
  source?: {
    channel: string;
    messageId: number;
    messageUrl: string;
    publishedAt: string | null;
  };
};

type CatalogPayload = {
  schemaVersion: number;
  categories: CatalogCategory[];
  products: CatalogProduct[];
};

type ProductImageData = {
  fileName: string;
  urlPath: string;
  alt: string;
  sortOrder: number;
  isCover: boolean;
};

const prisma = new PrismaClient();
const serviceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const catalogFile = path.resolve(
  process.env.CATALOG_FILE || path.join(serviceRoot, "catalog", "products.json"),
);
const catalogDirectory = path.dirname(catalogFile);
const uploadDirectory = path.resolve(process.env.UPLOAD_DIR || path.join(serviceRoot, "uploads"));

function assertCatalog(payload: unknown): asserts payload is CatalogPayload {
  if (!payload || typeof payload !== "object") {
    throw new Error("Catalog payload must be an object.");
  }

  const candidate = payload as Partial<CatalogPayload>;

  if (candidate.schemaVersion !== 1) {
    throw new Error(`Unsupported catalog schema version: ${candidate.schemaVersion}.`);
  }

  if (!Array.isArray(candidate.categories) || !Array.isArray(candidate.products)) {
    throw new Error("Catalog categories and products must be arrays.");
  }
}

function resolveCatalogImage(localPath: string) {
  const resolved = path.resolve(catalogDirectory, localPath);
  const allowedPrefix = `${catalogDirectory}${path.sep}`;

  if (!resolved.startsWith(allowedPrefix)) {
    throw new Error(`Catalog image escapes its directory: ${localPath}`);
  }

  return resolved;
}

async function importProduct(
  product: CatalogProduct,
  categoryIds: Map<string, number>,
) {
  const categoryId = categoryIds.get(product.categorySlug);

  if (!categoryId) {
    throw new Error(`Unknown category "${product.categorySlug}" for "${product.title}".`);
  }

  const imageData: ProductImageData[] = [];

  for (const image of product.images) {
    const sourcePath = resolveCatalogImage(image.localPath);
    const fileName = `telegram-${path.basename(image.localPath)}`;
    const destinationPath = path.join(uploadDirectory, fileName);

    await copyFile(sourcePath, destinationPath);
    imageData.push({
      fileName,
      urlPath: `/uploads/${fileName}`,
      alt: image.alt,
      sortOrder: image.sortOrder,
      isCover: image.isCover,
    });
  }

  await prisma.$transaction(async (transaction) => {
    const savedProduct = await transaction.product.upsert({
      where: { slug: product.slug },
      update: {
        title: product.title,
        categoryId,
        shortDescription: product.shortDescription,
        fullDescription: product.fullDescription,
        status: ProductStatus[product.status],
        isFeatured: product.isFeatured,
        basePrice: product.basePrice,
        priceFrom: product.priceFrom,
        leadTime: product.leadTime,
        materialNote: product.materialNote,
        deliveryNote: product.deliveryNote,
        paymentNote: product.paymentNote,
        sortOrder: product.sortOrder,
        sourceTelegramChannel: product.source?.channel ?? null,
        sourceTelegramMessageId: product.source?.messageId ?? null,
        sourceTelegramUrl: product.source?.messageUrl ?? "",
        sourceTelegramPublishedAt: product.source?.publishedAt
          ? new Date(product.source.publishedAt)
          : null,
      },
      create: {
        title: product.title,
        slug: product.slug,
        categoryId,
        shortDescription: product.shortDescription,
        fullDescription: product.fullDescription,
        status: ProductStatus[product.status],
        isFeatured: product.isFeatured,
        basePrice: product.basePrice,
        priceFrom: product.priceFrom,
        leadTime: product.leadTime,
        materialNote: product.materialNote,
        deliveryNote: product.deliveryNote,
        paymentNote: product.paymentNote,
        sortOrder: product.sortOrder,
        sourceTelegramChannel: product.source?.channel ?? null,
        sourceTelegramMessageId: product.source?.messageId ?? null,
        sourceTelegramUrl: product.source?.messageUrl ?? "",
        sourceTelegramPublishedAt: product.source?.publishedAt
          ? new Date(product.source.publishedAt)
          : null,
      },
    });

    await transaction.productVariant.deleteMany({
      where: { productId: savedProduct.id },
    });
    await transaction.productImage.deleteMany({
      where: { productId: savedProduct.id },
    });

    if (product.variants.length > 0) {
      await transaction.productVariant.createMany({
        data: product.variants.map((variant) => ({
          productId: savedProduct.id,
          label: variant.label,
          price: variant.price,
          description: variant.description,
          sortOrder: variant.sortOrder,
        })),
      });
    }

    if (imageData.length > 0) {
      await transaction.productImage.createMany({
        data: imageData.map((image) => ({
          productId: savedProduct.id,
          ...image,
        })),
      });
    }
  });
}

async function main() {
  const payload = JSON.parse(await readFile(catalogFile, "utf8")) as unknown;
  assertCatalog(payload);
  await mkdir(uploadDirectory, { recursive: true });

  const categoryIds = new Map<string, number>();

  for (const category of payload.categories) {
    const savedCategory = await prisma.category.upsert({
      where: { slug: category.slug },
      update: {
        name: category.name,
        description: category.description,
        sortOrder: category.sortOrder,
        isVisible: true,
      },
      create: {
        name: category.name,
        slug: category.slug,
        description: category.description,
        sortOrder: category.sortOrder,
        isVisible: true,
      },
    });

    categoryIds.set(category.slug, savedCategory.id);
  }

  for (const product of payload.products) {
    await importProduct(product, categoryIds);
  }

  console.log(
    `[catalog] imported ${payload.products.length} products from ${catalogFile}`,
  );
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
