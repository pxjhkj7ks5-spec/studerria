"use server";
import { redirect } from "next/navigation";
import { prisma } from "@/lib/prisma";
import { requireAdminSession, getAdminRoute } from "@/lib/auth";
import { deliverCustomRequestNotification } from "@/lib/custom-request-notification";
import { customRequestStatuses } from "@/lib/custom-request-validation";

export async function updateCustomRequest(form: FormData) {
  await requireAdminSession();
  const publicId = String(form.get("publicId") ?? "");
  if (!/^ND-[A-F0-9]{12}$/.test(publicId)) throw new Error("Некоректна заявка.");
  const status = String(form.get("status") ?? "");
  const priceText = String(form.get("agreedPrice") ?? "").trim();
  const agreedPrice = priceText === "" ? null : Number(priceText);
  const agreedLeadTime = String(form.get("agreedLeadTime") ?? "").trim();
  const ownerNote = String(form.get("ownerNote") ?? "").trim();
  const path = `${getAdminRoute()}/custom-requests/${publicId}`;
  if (!Object.hasOwn(customRequestStatuses,status) || (agreedPrice !== null && (!Number.isSafeInteger(agreedPrice) || agreedPrice < 0 || agreedPrice > 10_000_000)) || agreedLeadTime.length > 200 || ownerNote.length > 3000) redirect(`${path}?error=validation`);
  if (status === "quoted" && (agreedPrice === null || !agreedLeadTime)) redirect(`${path}?error=quote`);
  try { await prisma.customRequest.update({where:{publicId},data:{status:status as keyof typeof customRequestStatuses,agreedPrice,agreedLeadTime,ownerNote}}); }
  catch { redirect(`${path}?error=save`); }
  redirect(`${path}?ok=saved`);
}
export async function retryCustomRequestNotification(form: FormData) {
  await requireAdminSession();
  const publicId = String(form.get("publicId") ?? "");
  if (!/^ND-[A-F0-9]{12}$/.test(publicId)) throw new Error("Некоректна заявка.");
  const path = `${getAdminRoute()}/custom-requests/${publicId}`;
  try { await deliverCustomRequestNotification(publicId); }
  catch { redirect(`${path}?error=notification`); }
  redirect(`${path}?ok=notification`);
}
