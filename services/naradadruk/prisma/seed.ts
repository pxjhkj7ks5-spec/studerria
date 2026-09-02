import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  await prisma.siteSetting.upsert({
    where: { id: 1 },
    update: {
      materialsNote: "Високоякісний PETG.",
    },
    create: {
      id: 1,
      heroTitle: "3D друк, страйкбольні аксесуари та декор під ваш запит.",
      heroSubtitle:
        "Narada Druk робить серійні перевірені моделі та індивідуальні вироби для дому, сетапу й страйкболу без зайвого тертя в замовленні.",
      supportTitle: "Друкуємо те, що реально працює в щоденному користуванні.",
      supportBody:
        "Каталог зібраний як вітрина готових позицій, а нестандартні задачі домовляються напряму через Telegram.",
      materialsNote: "Високоякісний PETG.",
      leadTimeNote: "Від кількох годин до 3 днів залежно від складності.",
      deliveryNote: "Доставка по Україні, самовивіз у Києві.",
      paymentNote:
        "Реквізити для оплати надійдуть після підтвердження замовлення.",
      telegramUrl: process.env.TELEGRAM_CHANNEL_URL || "https://t.me/naradaprint",
      contactNote: "Для індивідуального виробу надішліть опис або фото прикладу в Telegram.",
    },
  });

  const categories = [
    {
      name: "Декор",
      slug: "dekor",
      description: "Тематичні вироби для столу, полиці та робочого простору.",
      sortOrder: 10,
    },
    {
      name: "Інше",
      slug: "inshe",
      description: "Практичні вироби, підставки, органайзери та аксесуари.",
      sortOrder: 20,
    },
    {
      name: "STRIKEBALL",
      slug: "strajkbol",
      description: "Аксесуари, кріплення та комплектуючі для спорядження.",
      sortOrder: 30,
    },
  ];

  for (const category of categories) {
    await prisma.category.upsert({
      where: { slug: category.slug },
      update: { ...category, isVisible: true },
      create: { ...category, isVisible: true },
    });
  }

  const activeCategories = await prisma.category.findMany({
    where: { slug: { in: categories.map((category) => category.slug) } },
    select: { id: true, slug: true },
  });
  const fallbackCategory = activeCategories.find((category) => category.slug === "inshe");
  if (fallbackCategory) {
    const activeIds = activeCategories.map((category) => category.id);
    await prisma.product.updateMany({
      where: { categoryId: { notIn: activeIds } },
      data: { categoryId: fallbackCategory.id },
    });
    await prisma.category.deleteMany({
      where: { id: { notIn: activeIds } },
    });
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
