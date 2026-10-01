import { PrismaClient } from "@prisma/client";
import { storefrontCategories, suggestedCategory } from "../src/lib/catalog-taxonomy";

const prisma = new PrismaClient();
async function main() {
  await prisma.$transaction(async (tx) => {
    for (const category of storefrontCategories) {
      await tx.category.upsert({ where: { slug: category.slug }, update: category, create: category });
    }
    const categories = await tx.category.findMany();
    const products = await tx.product.findMany({ include: { category: true } });
    for (const product of products) {
      const slug = suggestedCategory(product.title, product.category.slug);
      const target = categories.find((item) => item.slug === slug);
      if (target && target.id !== product.categoryId) await tx.product.update({ where: { id: product.id }, data: { categoryId: target.id } });
    }
    await tx.siteSetting.updateMany({ where: { heroTitle: "3D друк, страйкбольні аксесуари та декор під ваш запит." }, data: { heroTitle: "3D-друк для вашої задачі" } });
  });
}
main().catch(() => { console.error("Не вдалося оновити категорії storefront."); process.exitCode = 1; }).finally(() => prisma.$disconnect());
