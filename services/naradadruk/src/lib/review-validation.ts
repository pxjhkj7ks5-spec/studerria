import { z } from "zod";

function cleanText(value: string) {
  return value
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export const reviewInputSchema = z.object({
  displayName: z.string().transform(cleanText).pipe(z.string().max(60, "Ім’я не може перевищувати 60 символів.")),
  isAnonymous: z.boolean(),
  body: z.string()
    .transform(cleanText)
    .pipe(z.string().min(20, "Напишіть відгук щонайменше з 20 символів.").max(1500)),
}).superRefine((value, context) => {
  if (!value.isAnonymous && value.displayName.length > 0 && value.displayName.length < 2) {
    context.addIssue({
      code: "custom",
      path: ["displayName"],
      message: "Ім’я має містити щонайменше 2 символи або залиште поле порожнім.",
    });
  }
  const links = value.body.match(/(?:https?:\/\/|www\.)/gi)?.length ?? 0;
  if (links > 2) {
    context.addIssue({
      code: "custom",
      path: ["body"],
      message: "У відгуку може бути не більше двох посилань.",
    });
  }
});

export function getClientAddress(request: Request) {
  const realIp = request.headers.get("x-real-ip")?.trim();
  if (realIp) return realIp.slice(0, 80);
  const forwarded = request.headers.get("x-forwarded-for")
    ?.split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  return (forwarded?.[0] || "unknown").slice(0, 80);
}
