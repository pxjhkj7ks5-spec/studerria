import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { maxUploadSizeBytes } from "@/lib/constants";
import { slugify } from "@/lib/utils";

export type StoredUpload = {
  fileName: string;
  urlPath: string;
};

const allowedImageTypes = new Map<string, string>([
  ["image/avif", "avif"],
  ["image/gif", "gif"],
  ["image/jpeg", "jpg"],
  ["image/png", "png"],
  ["image/webp", "webp"],
]);

export function getUploadDir() {
  return process.env.UPLOAD_DIR ?? "./uploads";
}

export function resolveUploadDir() {
  const uploadDir = getUploadDir();

  if (path.isAbsolute(uploadDir)) {
    return uploadDir;
  }

  const normalizedRelativeDir = uploadDir.replace(/^\.?[\\/]+/, "");
  return path.join(/* turbopackIgnore: true */ process.cwd(), normalizedRelativeDir);
}

export function isSafeUploadFileName(fileName: string) {
  return /^[a-z0-9]+(?:-[a-z0-9]+)*-\d+\.(?:avif|gif|jpe?g|png|webp)$/i.test(fileName);
}

export function contentTypeForUpload(fileName: string) {
  const extension = path.extname(fileName).toLowerCase();

  switch (extension) {
    case ".avif":
      return "image/avif";
    case ".gif":
      return "image/gif";
    case ".jpg":
    case ".jpeg":
      return "image/jpeg";
    case ".png":
      return "image/png";
    case ".webp":
      return "image/webp";
    default:
      return "application/octet-stream";
  }
}

function extensionFromFile(file: File) {
  const mapped = allowedImageTypes.get(file.type);

  if (!mapped) {
    throw new Error("Дозволені лише JPG, PNG, WebP, GIF або AVIF.");
  }

  return mapped;
}

export async function saveProductImage(file: File, baseName: string): Promise<StoredUpload> {
  if (!allowedImageTypes.has(file.type)) {
    throw new Error("Дозволені лише JPG, PNG, WebP, GIF або AVIF.");
  }

  if (file.size > maxUploadSizeBytes) {
    throw new Error("Зображення завелике. Максимум 8 MB.");
  }

  const uploadDir = resolveUploadDir();
  await mkdir(uploadDir, { recursive: true });

  const fileName = `${slugify(baseName)}-${Date.now()}.${extensionFromFile(file)}`;
  const filePath = path.join(uploadDir, fileName);
  const buffer = Buffer.from(await file.arrayBuffer());

  await writeFile(filePath, buffer);

  return {
    fileName,
    urlPath: `/uploads/${fileName}`,
  };
}

export async function readUploadFile(fileName: string) {
  const absolutePath = path.join(resolveUploadDir(), fileName);
  return readFile(absolutePath);
}

export async function deleteUploadFile(fileName: string) {
  if (!isSafeUploadFileName(fileName)) {
    return;
  }

  try {
    await unlink(path.join(resolveUploadDir(), fileName));
  } catch {
    // ignore missing files
  }
}
