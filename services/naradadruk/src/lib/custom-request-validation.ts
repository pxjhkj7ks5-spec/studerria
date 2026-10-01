import { createHash } from "node:crypto";
import { z } from "zod";

export const customRequestMaxBytes = 10 * 1024 * 1024;
export const customRequestMaxFiles = 4;
export const customRequestStatuses = { new: "Нова", assessing: "Оцінюємо", quoted: "Пропозицію надіслано", closed: "Закрита" } as const;

const optionalText = (maximum: number) => z.string().trim().max(maximum).default("");
const validPhone = (value: string) => /^\+?[\d\s()\-]{9,22}$/.test(value) && /^\d{9,15}$/.test(value.replace(/\D/g, ""));
export const customRequestSchema = z.object({
  submissionKey: z.string().uuid("Оновіть сторінку й спробуйте ще раз."),
  mode: z.enum(["file", "model"]),
  name: z.string().trim().min(2, "Вкажіть ім’я.").max(80),
  telegramContact: z.string().trim().refine((value) => /^@[a-zA-Z0-9_]{5,32}$/.test(value) || validPhone(value), "Вкажіть Telegram @username або номер телефону."),
  phone: optionalText(30).refine((value) => !value || validPhone(value), "Перевірте номер телефону."),
  description: z.string().trim().min(10, "Опишіть задачу щонайменше десятьма символами.").max(3000),
  quantity: z.coerce.number().int().min(1).max(1000),
  dimensions: optionalText(200),
  desiredDate: optionalText(100),
  budget: z.preprocess((value) => value === "" || value === undefined || value === null ? null : Number(value), z.number().int().min(0).max(10_000_000).nullable()),
  modelUrl: optionalText(1000).refine((value) => { if (!value) return true; try { const url = new URL(value); return ["https:", "http:"].includes(url.protocol) && !url.username && !url.password; } catch { return false; } }, "Вкажіть повне посилання http або https."),
  productSlug: optionalText(160).refine((value) => !value || /^[a-z0-9-]+$/.test(value), "Посилання на товар некоректне."),
});
export type CustomRequestInput = z.infer<typeof customRequestSchema>;

const mimeTypes: Record<string, string> = { stl: "application/octet-stream", obj: "application/octet-stream", "3mf": "application/octet-stream", pdf: "application/pdf", jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", webp: "image/webp" };
export function validateAttachment(name: string, bytes: Buffer) {
  const extension = name.split(".").at(-1)?.toLowerCase() ?? "";
  if (!mimeTypes[extension] || !bytes.length) throw new Error("Дозволені непорожні STL, 3MF, OBJ, JPG, PNG, WebP або PDF.");
  if (bytes.length > customRequestMaxBytes) throw new Error("Загальний розмір файлів — до 10 МБ.");
  const prefix = bytes.subarray(0, 16);
  const signatures: Record<string, boolean> = {
    pdf: prefix.toString("ascii").startsWith("%PDF-"),
    jpg: prefix[0] === 0xff && prefix[1] === 0xd8 && prefix[2] === 0xff,
    jpeg: prefix[0] === 0xff && prefix[1] === 0xd8 && prefix[2] === 0xff,
    png: prefix.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10])),
    webp: prefix.subarray(0,4).toString() === "RIFF" && prefix.subarray(8,12).toString() === "WEBP",
    "3mf": prefix.subarray(0,4).equals(Buffer.from([80,75,3,4])),
  };
  if (extension in signatures && !signatures[extension]) throw new Error("Вміст файлу не відповідає його формату.");
  if (extension === "stl") {
    const binary = bytes.length >= 84 && 84 + bytes.readUInt32LE(80) * 50 === bytes.length;
    const ascii = /^\s*solid\b/i.test(bytes.subarray(0,256).toString()) && /endsolid\b/i.test(bytes.subarray(-512).toString());
    if (!binary && !ascii) throw new Error("Перевірте файл STL.");
  }
  if (extension === "obj" && (bytes.includes(0) || !/^\s*v\s+[-+.\d]/m.test(bytes.toString("utf8")))) throw new Error("Перевірте файл OBJ.");
  return { extension, mimeType: mimeTypes[extension], originalName: name.replace(/[\x00-\x1f\x7f/\\]/g, "_").slice(0,180) };
}

export function customRequestContentHash(input: CustomRequestInput, fileHashes: string[]) {
  const { submissionKey: _key, ...fields } = input;
  void _key;
  return createHash("sha256").update(JSON.stringify({ ...fields, files: [...fileHashes].sort() })).digest("hex");
}
