import { storefrontCategories } from "../src/lib/catalog-taxonomy";
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
      heroTitle: "3D-друк для вашої задачі",
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

  const categories = storefrontCategories;

  for (const category of categories) {
    await prisma.category.upsert({
      where: { slug: category.slug },
      update: { ...category, isVisible: true },
      create: { ...category, isVisible: true },
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
