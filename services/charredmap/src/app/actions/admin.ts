"use server";

import { timingSafeEqual } from "node:crypto";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { z } from "zod";
import {
  clearAdminSession,
  createAdminSession,
  getAdminPassword,
  getAdminRoute,
  getAdminStoriesRoute,
  requireAdminSession,
} from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";
import { occupationStatuses, publicationStatuses } from "@/lib/constants";
import { deleteStoryRecord, upsertCityRecord, upsertStoryRecord } from "@/lib/data";
import { localStorageAdapter } from "@/lib/storage";

export type ActionState = {
  error?: string;
};

const storySchema = z.object({
  storyId: z.string().optional(),
  cityId: z.string().optional(),
  cityMode: z.enum(["existing", "new"]),
  cityName: z.string().trim().min(2, "Вкажіть місто.").max(80, "Назва міста задовга."),
  oblast: z.string().trim().min(2, "Вкажіть область.").max(80, "Назва області задовга."),
  lat: z.coerce.number().min(43.5, "Широта поза межами України.").max(53.5),
  lng: z.coerce.number().min(20.5, "Довгота поза межами України.").max(40.8),
  occupationStatus: z.enum(occupationStatuses),
  title: z
    .string()
    .trim()
    .min(4, "Занадто короткий заголовок.")
    .max(140, "Заголовок має вміщатися в 140 символів."),
  body: z
    .string()
    .trim()
    .min(40, "Додайте повніший текст історії.")
    .max(20_000, "Текст занадто великий для одного матеріалу."),
  publicationStatus: z.enum(publicationStatuses),
});

const deleteStorySchema = z.object({
  storyId: z.string().trim().min(1, "Не вдалося визначити історію."),
});

function secureCompare(left: string, right: string) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

export async function loginAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const password = String(formData.get("password") ?? "");

  if (!secureCompare(password, getAdminPassword())) {
    return { error: "Невірний пароль." };
  }

  await createAdminSession();
  redirect(withBasePath(getAdminStoriesRoute()));
}

export async function logoutAction() {
  await clearAdminSession();
  redirect(withBasePath(getAdminRoute()));
}

export async function saveStoryAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  await requireAdminSession();

  const parsed = storySchema.safeParse({
    storyId: String(formData.get("storyId") ?? "") || undefined,
    cityId: String(formData.get("cityId") ?? "") || undefined,
    cityMode: String(formData.get("cityMode") ?? "new"),
    cityName: String(formData.get("cityName") ?? ""),
    oblast: String(formData.get("oblast") ?? ""),
    lat: String(formData.get("lat") ?? ""),
    lng: String(formData.get("lng") ?? ""),
    occupationStatus: String(formData.get("occupationStatus") ?? ""),
    title: String(formData.get("title") ?? ""),
    body: String(formData.get("body") ?? ""),
    publicationStatus: String(formData.get("publicationStatus") ?? "draft"),
  });

  if (!parsed.success) {
    return {
      error: parsed.error.issues[0]?.message ?? "Не вдалося зберегти історію.",
    };
  }

  if (parsed.data.cityMode === "existing" && !parsed.data.cityId) {
    return {
      error: "Оберіть існуюче місто або переключіться на створення нового.",
    };
  }

  let coverImageUrl: string | null | undefined;
  const coverImage = formData.get("coverImage");

  let story: Awaited<ReturnType<typeof upsertStoryRecord>>;

  try {
    if (coverImage instanceof File && coverImage.size > 0) {
      const storedUpload = await localStorageAdapter.saveCoverImage(
        coverImage,
        parsed.data.title,
      );
      coverImageUrl = storedUpload.url;
    }

    const city = await upsertCityRecord({
      cityId: parsed.data.cityMode === "existing" ? parsed.data.cityId : undefined,
      cityName: parsed.data.cityName,
      oblast: parsed.data.oblast,
      lat: parsed.data.lat,
      lng: parsed.data.lng,
      occupationStatus: parsed.data.occupationStatus,
    });

    story = await upsertStoryRecord({
      storyId: parsed.data.storyId,
      cityId: city.id,
      title: parsed.data.title,
      body: parsed.data.body,
      coverImageUrl,
      publicationStatus: parsed.data.publicationStatus,
    });
  } catch (error) {
    if (error instanceof Error) {
      return { error: error.message };
    }

    return { error: "Не вдалося зберегти історію." };
  }

  const adminBasePath = withBasePath(getAdminRoute());
  const adminStoriesPath = withBasePath(getAdminStoriesRoute());

  revalidatePath(withBasePath("/"));
  revalidatePath(adminBasePath);
  revalidatePath(adminStoriesPath);
  revalidatePath(withBasePath(`/stories/${story.slug}`));

  redirect(withBasePath(`${getAdminStoriesRoute()}?saved=1`));
}

export async function deleteStoryAction(formData: FormData) {
  await requireAdminSession();

  const parsed = deleteStorySchema.safeParse({
    storyId: String(formData.get("storyId") ?? ""),
  });

  if (!parsed.success) {
    redirect(withBasePath(`${getAdminStoriesRoute()}?deleted=0`));
  }

  const deletedStory = await deleteStoryRecord(parsed.data.storyId);

  revalidatePath(withBasePath("/"));
  revalidatePath(withBasePath(getAdminRoute()));
  revalidatePath(withBasePath(getAdminStoriesRoute()));
  revalidatePath(withBasePath(`/stories/${deletedStory.slug}`));

  redirect(withBasePath(`${getAdminStoriesRoute()}?deleted=1`));
}
