"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { z } from "zod";
import {
  getAdminRoute,
  getAdminStoriesRoute,
  getAdminTerritoriesRoute,
  requireAdminSession,
} from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";
import { saveOccupationOverlay } from "@/lib/occupation-overlay";

const occupationOverlaySchema = z.object({
  overlayGeoJson: z.string().min(1),
});

export async function saveOccupationOverlayAction(formData: FormData) {
  await requireAdminSession();

  const parsed = occupationOverlaySchema.safeParse({
    overlayGeoJson: String(formData.get("overlayGeoJson") ?? ""),
  });

  if (!parsed.success) {
    redirect(`${getAdminTerritoriesRoute()}?saved=0`);
  }

  try {
    const overlay = JSON.parse(parsed.data.overlayGeoJson);
    await saveOccupationOverlay(overlay);
  } catch (error) {
    console.error("saveOccupationOverlayAction failed:", error);
    redirect(`${getAdminTerritoriesRoute()}?saved=0`);
  }

  revalidatePath(withBasePath("/"));
  revalidatePath(withBasePath(getAdminRoute()));
  revalidatePath(withBasePath(getAdminStoriesRoute()));
  revalidatePath(withBasePath(getAdminTerritoriesRoute()));

  redirect(`${getAdminTerritoriesRoute()}?saved=1`);
}
