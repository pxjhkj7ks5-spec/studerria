import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PrismaClient } from "@prisma/client";

type PricingVariant = {
  label: string;
  price: number;
};

type PricingProduct = {
  slug: string;
  basePrice: number | null;
  priceFrom: boolean;
  variants?: PricingVariant[];
};

type PricingPayload = {
  schemaVersion: number;
  products: PricingProduct[];
};

const prisma = new PrismaClient();
const serviceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pricingFile = path.resolve(
  process.env.PRICING_FILE || path.join(serviceRoot, "catalog", "pricing.json"),
);

function assertPricing(payload: unknown): asserts payload is PricingPayload {
  if (!payload || typeof payload !== "object") {
    throw new Error("Pricing payload must be an object.");
  }

  const candidate = payload as Partial<PricingPayload>;
  if (candidate.schemaVersion !== 1 || !Array.isArray(candidate.products)) {
    throw new Error("Unsupported pricing payload.");
  }

  const slugs = new Set<string>();
  for (const product of candidate.products) {
    if (!product.slug || slugs.has(product.slug)) {
      throw new Error(`Pricing contains an empty or duplicate slug: ${product.slug}.`);
    }
    if (product.basePrice !== null && (!Number.isInteger(product.basePrice) || product.basePrice < 0)) {
      throw new Error(`Invalid price for ${product.slug}.`);
    }
    slugs.add(product.slug);
  }
}

function replacePriceLabel(value: string, oldPrice: number, newPrice: number) {
  if (oldPrice === newPrice) return value;
  return value.replaceAll(`${oldPrice} грн`, `${newPrice} грн`);
}

async function main() {
  const payload = JSON.parse(await readFile(pricingFile, "utf8")) as unknown;
  assertPricing(payload);

  const existingProducts = await prisma.product.findMany({
    where: { slug: { in: payload.products.map((product) => product.slug) } },
    include: { variants: true },
  });
  const productsBySlug = new Map(existingProducts.map((product) => [product.slug, product]));
  const missingProducts = payload.products
    .filter((product) => !productsBySlug.has(product.slug))
    .map((product) => product.slug);

  if (missingProducts.length > 0) {
    throw new Error(`Pricing products not found: ${missingProducts.join(", ")}.`);
  }

  for (const pricing of payload.products) {
    const product = productsBySlug.get(pricing.slug)!;
    const variantsByLabel = new Map(product.variants.map((variant) => [variant.label, variant]));
    const missingVariants = (pricing.variants ?? [])
      .filter((variant) => !variantsByLabel.has(variant.label))
      .map((variant) => variant.label);

    if (missingVariants.length > 0) {
      throw new Error(`Pricing variants not found for ${pricing.slug}: ${missingVariants.join(", ")}.`);
    }
  }

  await prisma.$transaction(async (transaction) => {
    for (const pricing of payload.products) {
      const product = productsBySlug.get(pricing.slug)!;
      let fullDescription = product.fullDescription;
      let telegramDescription = product.telegramDescription;

      if (product.basePrice !== null && pricing.basePrice !== null) {
        fullDescription = replacePriceLabel(fullDescription, product.basePrice, pricing.basePrice);
        telegramDescription = replacePriceLabel(
          telegramDescription,
          product.basePrice,
          pricing.basePrice,
        );
      }

      for (const variantPricing of pricing.variants ?? []) {
        const variant = product.variants.find((item) => item.label === variantPricing.label)!;
        fullDescription = replacePriceLabel(fullDescription, variant.price, variantPricing.price);
        telegramDescription = replacePriceLabel(
          telegramDescription,
          variant.price,
          variantPricing.price,
        );
      }

      await transaction.product.update({
        where: { id: product.id },
        data: {
          basePrice: pricing.basePrice,
          priceFrom: pricing.priceFrom,
          saleEnabled: false,
          salePrice: null,
          salePercent: null,
          saleStartsAt: null,
          saleEndsAt: null,
          fullDescription,
          telegramDescription,
        },
      });

      for (const variantPricing of pricing.variants ?? []) {
        const variant = product.variants.find((item) => item.label === variantPricing.label)!;
        await transaction.productVariant.update({
          where: { id: variant.id },
          data: { price: variantPricing.price },
        });
      }
    }
  });

  console.log(`[pricing] imported ${payload.products.length} product prices from ${pricingFile}`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
