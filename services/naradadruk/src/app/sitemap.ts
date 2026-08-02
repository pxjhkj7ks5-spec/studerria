import type { MetadataRoute } from "next";
import { ProductStatus } from "@prisma/client";
import { absoluteSiteUrl } from "@/lib/site-url";
import { prisma } from "@/lib/prisma";

export const dynamic = "force-dynamic";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const [categories, products] = await Promise.all([
    prisma.category.findMany({
      where: { isVisible: true },
      select: { slug: true, updatedAt: true },
    }),
    prisma.product.findMany({
      where: { status: ProductStatus.published, category: { isVisible: true } },
      select: { slug: true, updatedAt: true },
    }),
  ]);

  const staticPages: MetadataRoute.Sitemap = [
    { url: absoluteSiteUrl(), changeFrequency: "weekly", priority: 1 },
    { url: absoluteSiteUrl("/catalog"), changeFrequency: "daily", priority: 0.9 },
    { url: absoluteSiteUrl("/reviews"), changeFrequency: "weekly", priority: 0.6 },
  ];

  return [
    ...staticPages,
    ...categories.map((category) => ({
      url: absoluteSiteUrl(`/category/${category.slug}`),
      lastModified: category.updatedAt,
      changeFrequency: "weekly" as const,
      priority: 0.75,
    })),
    ...products.map((product) => ({
      url: absoluteSiteUrl(`/product/${product.slug}`),
      lastModified: product.updatedAt,
      changeFrequency: "weekly" as const,
      priority: 0.8,
    })),
  ];
}
