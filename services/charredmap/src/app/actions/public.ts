"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { z } from "zod";
import { getAdminRoute, getAdminStoriesRoute } from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";
import { occupationStatuses } from "@/lib/constants";
import { resolveSubmissionCityRecord, upsertStoryRecord } from "@/lib/data";

export type PublicSubmissionState = {
  error?: string;
};

const submissionSchema = z.object({
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
    .min(120, "Для модерації потрібен повніший текст щонайменше на 120 символів.")
    .max(20_000, "Текст занадто великий для одного матеріалу."),
  submitterName: z.string().trim().min(2, "Вкажіть своє імʼя.").max(80, "Імʼя задовге."),
  submitterContact: z
    .string()
    .trim()
    .min(3, "Додайте контакт для зворотного звʼязку.")
    .max(160, "Контакт занадто довгий."),
  website: z.string().optional(),
});

export async function submitStoryAction(
  _previousState: PublicSubmissionState,
  formData: FormData,
): Promise<PublicSubmissionState> {
  const parsed = submissionSchema.safeParse({
    cityId: String(formData.get("cityId") ?? "") || undefined,
    cityMode: String(formData.get("cityMode") ?? "new"),
    cityName: String(formData.get("cityName") ?? ""),
    oblast: String(formData.get("oblast") ?? ""),
    lat: String(formData.get("lat") ?? ""),
    lng: String(formData.get("lng") ?? ""),
    occupationStatus: String(formData.get("occupationStatus") ?? ""),
    title: String(formData.get("title") ?? ""),
    body: String(formData.get("body") ?? ""),
    submitterName: String(formData.get("submitterName") ?? ""),
    submitterContact: String(formData.get("submitterContact") ?? ""),
    website: String(formData.get("website") ?? ""),
  });

  if (!parsed.success) {
    return {
      error: parsed.error.issues[0]?.message ?? "Не вдалося надіслати матеріал.",
    };
  }

  if (parsed.data.website?.trim()) {
    redirect(withBasePath("/submit?submitted=1"));
  }

  if (parsed.data.cityMode === "existing" && !parsed.data.cityId) {
    return {
      error: "Оберіть місто зі списку або продовжіть як новий запис.",
    };
  }

  try {
    const city = await resolveSubmissionCityRecord({
      cityId: parsed.data.cityMode === "existing" ? parsed.data.cityId : undefined,
      cityName: parsed.data.cityName,
      oblast: parsed.data.oblast,
      lat: parsed.data.lat,
      lng: parsed.data.lng,
      occupationStatus: parsed.data.occupationStatus,
    });

    await upsertStoryRecord({
      cityId: city.id,
      title: parsed.data.title,
      body: parsed.data.body,
      publicationStatus: "submitted",
      submitterName: parsed.data.submitterName,
      submitterContact: parsed.data.submitterContact,
    });
  } catch (error) {
    if (error instanceof Error) {
      return { error: error.message };
    }

    return { error: "Не вдалося надіслати матеріал." };
  }

  revalidatePath(withBasePath(getAdminRoute()));
  revalidatePath(withBasePath(getAdminStoriesRoute()));
  redirect(withBasePath("/submit?submitted=1"));
}
