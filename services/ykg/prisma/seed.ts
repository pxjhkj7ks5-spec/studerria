import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  await prisma.siteSetting.upsert({
    where: { id: 1 },
    update: {},
    create: {
      id: 1,
      heroTitle: "Спорядження зі своїм знаком.",
      heroSubtitle: "Офіційний мерч Young Killers Group — короткі серії, чесна наявність і доставка по Україні.",
      supportTitle: "Речі, що тримають ідентичність групи.",
      supportBody: "Невеликий каталог кепок, патчів і колаборацій без масового шуму.",
      materialsNote: "Матеріали й виконання зазначаються окремо для кожної позиції.",
      leadTimeNote: "Термін підтверджує менеджер після оформлення.",
      deliveryNote: "Нова пошта: відділення, поштомат або курʼєр.",
      paymentNote: "Післяплата або переказ після підтвердження замовлення.",
      telegramUrl: "https://www.instagram.com/youngkillersgroup_store/",
      contactNote: "Питання щодо позиції можна надіслати в Instagram YKG Store.",
    },
  });

  const categories = [
    { name: "Кепки", slug: "kepky", description: "Головні убори та колабораційні випуски.", sortOrder: 10 },
    { name: "Патчі", slug: "patchi", description: "Вишиті та PVC-патчі YKG.", sortOrder: 20 },
    { name: "Інше", slug: "inshe", description: "Інші позиції та майбутні дропи.", sortOrder: 30 },
  ];
  for (const category of categories) {
    await prisma.category.upsert({
      where: { slug: category.slug },
      update: { ...category, isVisible: true },
      create: { ...category, isVisible: true },
    });
  }

  const categoryBySlug = new Map(
    (await prisma.category.findMany({ select: { id: true, slug: true } })).map((category) => [category.slug, category.id]),
  );
  const drafts = [
    {
      title: "Кепка G.B.C. × YKG — уточнити",
      slug: "gbc-ykg-cap-draft",
      categorySlug: "kepky",
      sourceUrl: "https://www.instagram.com/good.boys.club_store/p/DWyTrgOjThD/",
    },
    {
      title: "Патч Young Killers Group — уточнити",
      slug: "ykg-patch-draft",
      categorySlug: "patchi",
      sourceUrl: "https://www.instagram.com/youngkillersgroup_store/p/DNOTMM5tygU/",
    },
    {
      title: "Колабораційний патч YKG — уточнити",
      slug: "ykg-collaboration-patch-draft",
      categorySlug: "patchi",
      sourceUrl: "https://www.instagram.com/youngkillersgroup_store/p/DIEBCUYNRS8/",
    },
  ];
  for (const draft of drafts) {
    const categoryId = categoryBySlug.get(draft.categorySlug);
    if (!categoryId) continue;
    await prisma.product.upsert({
      where: { slug: draft.slug },
      update: {},
      create: {
        title: draft.title,
        slug: draft.slug,
        categoryId,
        status: "draft",
        shortDescription: "Чернетка за публічним Instagram-референсом. Дані потребують підтвердження.",
        fullDescription: "Не публікувати до підтвердження назви, ціни, варіантів, залишку та завантаження дозволених оригінальних фото.",
        sourceUrl: draft.sourceUrl,
      },
    });
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => prisma.$disconnect());
