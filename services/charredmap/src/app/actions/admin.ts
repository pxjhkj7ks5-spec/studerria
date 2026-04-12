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
import { upsertCityRecord, upsertStoryRecord } from "@/lib/data";
import { localStorageAdapter } from "@/lib/storage";

export type ActionState = {
  error?: string;
};

const storySchema = z.object({
  storyId: z.string().optional(),
  cityId: z.string().optional(),
  cityMode: z.enum(["existing", "new"]),
  cityName: z.string().trim().min(2, "Вкажіть місто."),
  oblast: z.string().trim().min(2, "Вкажіть область."),
  lat: z.coerce.number().min(43.5, "Широта поза межами України.").max(53.5),
  lng: z.coerce.number().min(20.5, "Довгота поза межами України.").max(40.8),
  occupationStatus: z.enum(occupationStatuses),
  title: z.string().trim().min(4, "Занадто короткий заголовок."),
  body: z.string().trim().min(40, "Додайте повніший текст історії."),
  publicationStatus: z.enum(publicationStatuses),
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
  redirect(getAdminStoriesRoute());
}

export async function logoutAction() {
  await clearAdminSession();
  redirect(getAdminRoute());
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

    const story = await upsertStoryRecord({
      storyId: parsed.data.storyId,
      cityId: city.id,
      title: parsed.data.title,
      body: parsed.data.body,
      coverImageUrl,
      publicationStatus: parsed.data.publicationStatus,
    });

    const adminBasePath = withBasePath(getAdminRoute());
    const adminStoriesPath = withBasePath(getAdminStoriesRoute());

    revalidatePath(withBasePath("/"));
    revalidatePath(adminBasePath);
    revalidatePath(adminStoriesPath);
    revalidatePath(withBasePath(`/stories/${story.slug}`));

    redirect(`${getAdminStoriesRoute()}?saved=1`);
  } catch (error) {
    if (error instanceof Error) {
      return { error: error.message };
    }

    return { error: "Не вдалося зберегти історію." };
  }
}
