import type { Prisma } from "@prisma/client";
import type { PublicationStatus } from "@/lib/constants";
import { ensureCharredmapDatabase, prisma } from "@/lib/prisma";
import { excerpt, slugify } from "@/lib/utils";

type StoryWithCity = Prisma.StoryGetPayload<{
  include: {
    city: true;
  };
}>;

export type SerializedStory = {
  id: string;
  slug: string;
  title: string;
  body: string;
  excerpt: string;
  coverImageUrl: string | null;
  publicationStatus: PublicationStatus;
  publishedAt: string | null;
  createdAt: string;
  updatedAt: string;
  city: {
    id: string;
    name: string;
    slug: string;
    oblast: string;
    lat: number;
    lng: number;
    occupationStatus: "occupied" | "deoccupied";
  };
};

function serializeStory(story: StoryWithCity): SerializedStory {
  return {
    id: story.id,
    slug: story.slug,
    title: story.title,
    body: story.body,
    excerpt: excerpt(story.body),
    coverImageUrl: story.coverImageUrl,
    publicationStatus: story.publicationStatus,
    publishedAt: story.publishedAt?.toISOString() ?? null,
    createdAt: story.createdAt.toISOString(),
    updatedAt: story.updatedAt.toISOString(),
    city: {
      id: story.city.id,
      name: story.city.name,
      slug: story.city.slug,
      oblast: story.city.oblast,
      lat: story.city.lat,
      lng: story.city.lng,
      occupationStatus: story.city.occupationStatus,
    },
  };
}

function isDatabaseNotReady(error: unknown) {
  return error instanceof Error && /table|database|schema|engine/i.test(error.message);
}

export async function getPublishedStories() {
  await ensureCharredmapDatabase();

  try {
    const stories = await prisma.story.findMany({
      where: { publicationStatus: "published" },
      include: { city: true },
      orderBy: [{ publishedAt: "desc" }, { updatedAt: "desc" }],
    });

    return stories.map((story) => serializeStory(story));
  } catch (error) {
    if (isDatabaseNotReady(error)) {
      return [];
    }

    throw error;
  }
}

export async function getPublishedStoryBySlug(slug: string) {
  await ensureCharredmapDatabase();

  try {
    const story = await prisma.story.findFirst({
      where: {
        slug,
        publicationStatus: "published",
      },
      include: { city: true },
    });

    return story ? serializeStory(story) : null;
  } catch (error) {
    if (isDatabaseNotReady(error)) {
      return null;
    }

    throw error;
  }
}

export async function getAdminStories() {
  await ensureCharredmapDatabase();

  try {
    const stories = await prisma.story.findMany({
      include: { city: true },
      orderBy: [{ updatedAt: "desc" }, { createdAt: "desc" }],
    });

    return stories.map((story) => serializeStory(story));
  } catch (error) {
    if (isDatabaseNotReady(error)) {
      return [];
    }

    throw error;
  }
}

export async function getAdminStoryById(id: string) {
  await ensureCharredmapDatabase();

  try {
    const story = await prisma.story.findUnique({
      where: { id },
      include: { city: true },
    });

    return story ? serializeStory(story) : null;
  } catch (error) {
    if (isDatabaseNotReady(error)) {
      return null;
    }

    throw error;
  }
}

export async function getAdminCities() {
  await ensureCharredmapDatabase();

  try {
    return await prisma.city.findMany({
      orderBy: [{ name: "asc" }],
      select: {
        id: true,
        name: true,
        slug: true,
        oblast: true,
        lat: true,
        lng: true,
        occupationStatus: true,
      },
    });
  } catch (error) {
    if (isDatabaseNotReady(error)) {
      return [];
    }

    throw error;
  }
}

export async function getPublishedStats() {
  await ensureCharredmapDatabase();

  try {
    const [stories, cities] = await Promise.all([
      prisma.story.count({ where: { publicationStatus: "published" } }),
      prisma.city.count(),
    ]);

    return {
      stories,
      cities,
    };
  } catch (error) {
    if (isDatabaseNotReady(error)) {
      return {
        stories: 0,
        cities: 0,
      };
    }

    throw error;
  }
}

export async function createUniqueStorySlug(title: string, storyId?: string) {
  return createUniqueSlug("story", title, storyId);
}

export async function createUniqueCitySlug(name: string, cityId?: string) {
  return createUniqueSlug("city", name, cityId);
}

async function createUniqueSlug(
  model: "story" | "city",
  source: string,
  excludeId?: string,
) {
  await ensureCharredmapDatabase();

  const baseSlug = slugify(source);
  let attempt = 0;

  while (attempt < 100) {
    const candidate = attempt === 0 ? baseSlug : `${baseSlug}-${attempt + 1}`;

    const existing =
      model === "story"
        ? await prisma.story.findFirst({
            where: {
              slug: candidate,
              ...(excludeId ? { NOT: { id: excludeId } } : {}),
            },
            select: { id: true },
          })
        : await prisma.city.findFirst({
            where: {
              slug: candidate,
              ...(excludeId ? { NOT: { id: excludeId } } : {}),
            },
            select: { id: true },
          });

    if (!existing) {
      return candidate;
    }

    attempt += 1;
  }

  throw new Error("Не вдалося згенерувати унікальний slug.");
}

export async function upsertCityRecord(input: {
  cityId?: string;
  cityName: string;
  oblast: string;
  lat: number;
  lng: number;
  occupationStatus: "occupied" | "deoccupied";
}) {
  await ensureCharredmapDatabase();

  if (input.cityId) {
    return prisma.city.update({
      where: { id: input.cityId },
      data: {
        name: input.cityName,
        oblast: input.oblast,
        lat: input.lat,
        lng: input.lng,
        occupationStatus: input.occupationStatus,
      },
    });
  }

  const slug = await createUniqueCitySlug(input.cityName);

  return prisma.city.create({
    data: {
      name: input.cityName,
      slug,
      oblast: input.oblast,
      lat: input.lat,
      lng: input.lng,
      occupationStatus: input.occupationStatus,
    },
  });
}

export async function upsertStoryRecord(input: {
  storyId?: string;
  cityId: string;
  title: string;
  body: string;
  coverImageUrl?: string | null;
  publicationStatus: PublicationStatus;
}) {
  await ensureCharredmapDatabase();

  if (input.storyId) {
    const existing = await prisma.story.findUniqueOrThrow({
      where: { id: input.storyId },
      select: {
        slug: true,
        publishedAt: true,
        coverImageUrl: true,
      },
    });

    return prisma.story.update({
      where: { id: input.storyId },
      data: {
        title: input.title,
        body: input.body,
        cityId: input.cityId,
        coverImageUrl: input.coverImageUrl ?? existing.coverImageUrl,
        publicationStatus: input.publicationStatus,
        publishedAt:
          input.publicationStatus === "published"
            ? existing.publishedAt ?? new Date()
            : null,
      },
      include: { city: true },
    });
  }

  const slug = await createUniqueStorySlug(input.title);

  return prisma.story.create({
    data: {
      title: input.title,
      slug,
      body: input.body,
      cityId: input.cityId,
      coverImageUrl: input.coverImageUrl ?? null,
      publicationStatus: input.publicationStatus,
      publishedAt: input.publicationStatus === "published" ? new Date() : null,
    },
    include: { city: true },
  });
}
