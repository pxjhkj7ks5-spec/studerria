import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { maxUploadSizeBytes } from "@/lib/constants";
import { slugify } from "@/lib/utils";

export type StoredUpload = {
  fileName: string;
  url: string;
};

export interface StorageAdapter {
  saveCoverImage(file: File, baseName: string): Promise<StoredUpload>;
}

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
  return path.resolve(process.cwd(), getUploadDir());
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
    case ".jpeg":
    case ".jpg":
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
  const mappedExtension = allowedImageTypes.get(file.type);

  if (mappedExtension) {
    return mappedExtension;
  }

  throw new Error("Дозволені тільки JPG, PNG, WebP, GIF або AVIF.");
}

export const localStorageAdapter: StorageAdapter = {
  async saveCoverImage(file, baseName) {
    if (!allowedImageTypes.has(file.type)) {
      throw new Error("Дозволені тільки JPG, PNG, WebP, GIF або AVIF.");
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
      url: `/uploads/${fileName}`,
    };
  },
};
