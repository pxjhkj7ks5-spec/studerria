import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { resolveUploadDir } from "@/lib/storage";

export function privateAttachmentPath(fileName: string) {
  if (!/^[a-f0-9-]{36}\.(stl|obj|3mf|pdf|jpe?g|png|webp)$/.test(fileName)) throw new Error("Некоректне вкладення.");
  return path.join(resolveUploadDir(), "private-custom", fileName);
}
export async function savePrivateAttachment(bytes: Buffer, extension: string) {
  const fileName = `${randomUUID()}.${extension}`;
  const filePath = privateAttachmentPath(fileName);
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, bytes, { flag: "wx", mode: 0o600 });
  return fileName;
}
export async function deletePrivateAttachment(fileName: string) { await unlink(privateAttachmentPath(fileName)).catch(() => undefined); }
export async function readPrivateAttachment(fileName: string) { return readFile(privateAttachmentPath(fileName)); }
