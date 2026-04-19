import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  await prisma.siteSetting.upsert({
    where: { id: 1 },
    update: {},
    create: {
      id: 1,
      heroTitle: "3D друк, страйкбольні аксесуари та декор під ваш запит.",
      heroSubtitle:
        "Narada Druk робить серійні перевірені моделі та індивідуальні вироби для дому, сетапу й страйкболу без зайвого тертя в замовленні.",
      supportTitle: "Друкуємо те, що реально працює в щоденному користуванні.",
      supportBody:
        "Каталог зібраний як вітрина готових позицій, а нестандартні задачі домовляються напряму через Telegram.",
      materialsNote: "PETG та інші практичні матеріали під задачу.",
      leadTimeNote: "Від кількох годин до 3 днів залежно від складності.",
      deliveryNote: "Доставка по Україні, самовивіз у Києві.",
      paymentNote: "Оплата на картку: часткова або повна передплата.",
      telegramUrl: process.env.TELEGRAM_CHANNEL_URL || "https://web.telegram.org/k/#@naradaprint",
      contactNote: "Для індивідуального виробу надішліть опис або фото прикладу в Telegram.",
    },
  });

  const categories = [
    {
      name: "3D друк",
      slug: "3d-druk",
      description: "Функціональні деталі, кріплення та кастомні рішення під техніку або побут.",
      sortOrder: 10,
    },
    {
      name: "Страйкбол",
      slug: "strajkbol",
      description: "Аксесуари та комплектуючі для спорядження, приводів і комфортнішого користування.",
      sortOrder: 20,
    },
    {
      name: "Декор",
      slug: "dekor",
      description: "Практичний і атмосферний декор для робочого простору або дому.",
      sortOrder: 30,
    },
    {
      name: "Інше",
      slug: "inshe",
      description: "Різні корисні вироби, які не вкладаються в одну категорію.",
      sortOrder: 40,
    },
  ];

  for (const category of categories) {
    await prisma.category.upsert({
      where: { slug: category.slug },
      update: {},
      create: category,
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
