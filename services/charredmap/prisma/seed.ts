import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  const cityData = [
    {
      name: "Ізюм",
      slug: "izium",
      oblast: "Харківська область",
      lat: 49.208,
      lng: 37.256,
      occupationStatus: "deoccupied" as const,
    },
    {
      name: "Мелітополь",
      slug: "melitopol",
      oblast: "Запорізька область",
      lat: 46.848,
      lng: 35.365,
      occupationStatus: "occupied" as const,
    },
    {
      name: "Херсон",
      slug: "kherson",
      oblast: "Херсонська область",
      lat: 46.635,
      lng: 32.617,
      occupationStatus: "deoccupied" as const,
    },
  ];

  const cities: Array<{
    id: string;
    slug: string;
  }> = [];

  for (const city of cityData) {
    const record = await prisma.city.upsert({
      where: { slug: city.slug },
      update: city,
      create: {
        ...city,
      },
    });

    cities.push(record);
  }

  const stories = [
    {
      citySlug: "izium",
      slug: "povernennia-do-iziuma",
      title: "Повернення до Ізюма",
      body: `Коли ми вперше знову зайшли на подвір'я, тиша була гучнішою за вибухи.\n\nМи почали відновлення з фотоальбому, який дивом лишився цілим. Пізніше сусіди повернулися і кожен приносив маленьку історію про те, що вдалося зберегти.`,
      publicationStatus: "published" as const,
    },
    {
      citySlug: "melitopol",
      slug: "lysty-z-melitopolia",
      title: "Листи з Мелітополя",
      body: `Ми записуємо побут у місті маленькими фрагментами, щоб нічого не зникло без сліду.\n\nКожне коротке повідомлення про школу, двір чи ринок стає частиною великої пам'яті про місто.`,
      publicationStatus: "published" as const,
    },
    {
      citySlug: "kherson",
      slug: "svitlo-v-khersoni",
      title: "Світло в Херсоні",
      body: `Після деокупації місто знову вчиться дихати вголос.\n\nНайважливішими стали звичайні речі: увімкнене світло, відчинене вікно, знайомий маршрут до річки.`,
      publicationStatus: "draft" as const,
    },
  ];

  for (const story of stories) {
    const city = cities.find((entry) => entry.slug === story.citySlug);

    if (!city) {
      continue;
    }

    await prisma.story.upsert({
      where: { slug: story.slug },
      update: {
        title: story.title,
        body: story.body,
        cityId: city.id,
        publicationStatus: story.publicationStatus,
        publishedAt: story.publicationStatus === "published" ? new Date() : null,
      },
      create: {
        title: story.title,
        slug: story.slug,
        body: story.body,
        cityId: city.id,
        publicationStatus: story.publicationStatus,
        publishedAt: story.publicationStatus === "published" ? new Date() : null,
      },
    });
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
