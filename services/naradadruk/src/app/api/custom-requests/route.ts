import { createHash, randomUUID } from "node:crypto";
import { Prisma } from "@prisma/client";
import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { createPrivacyHash } from "@/lib/auth";
import { getTrustedClientAddress, hashAnalyticsIp } from "@/lib/analytics-ip";
import { customRequestSchema, customRequestContentHash, customRequestMaxBytes, customRequestMaxFiles, validateAttachment } from "@/lib/custom-request-validation";
import { deletePrivateAttachment, savePrivateAttachment } from "@/lib/custom-request-storage";
import { deliverCustomRequestNotification } from "@/lib/custom-request-notification";

export const runtime = "nodejs";
const maximumBodyBytes = customRequestMaxBytes + 128 * 1024;
class SubmissionError extends Error { constructor(message: string, readonly status = 400) { super(message); } }

async function boundedFormData(request: Request) {
  const reader = request.body?.getReader();
  if (!reader) throw new SubmissionError("Форма порожня.");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximumBodyBytes) { await reader.cancel(); throw new SubmissionError("Загальний розмір файлів — до 10 МБ.", 413); }
      chunks.push(value);
    }
    return await new Request(request.url, { method: "POST", headers: { "content-type": request.headers.get("content-type") ?? "" }, body: Buffer.concat(chunks) }).formData();
  } catch (error) { if (error instanceof SubmissionError) throw error; throw new SubmissionError("Не вдалося прочитати форму."); }
}

export async function POST(request: Request) {
  const storedFiles: string[] = [];
  let saved = false;
  try {
    if (request.headers.get("sec-fetch-site") === "cross-site") throw new SubmissionError("Надішліть заявку з нашого сайту.",403);
    if (Number(request.headers.get("content-length") ?? 0) > maximumBodyBytes) throw new SubmissionError("Загальний розмір файлів — до 10 МБ.",413);
    const form = await boundedFormData(request);
    if (String(form.get("website") ?? "").trim()) throw new SubmissionError("Не вдалося надіслати заявку.");
    const fields = Object.fromEntries([...form.entries()].filter(([key, value]) => key !== "files" && typeof value === "string"));
    const parsed = customRequestSchema.safeParse(fields);
    if (!parsed.success) throw new SubmissionError(parsed.error.issues[0]?.message ?? "Перевірте поля.");
    const input = parsed.data;
    const files = form.getAll("files").filter((item): item is File => item instanceof File && item.size > 0);
    if (files.length > customRequestMaxFiles) throw new SubmissionError("Додайте не більше чотирьох файлів.");
    if (files.reduce((sum,file) => sum + file.size,0) > customRequestMaxBytes) throw new SubmissionError("Загальний розмір файлів — до 10 МБ.",413);
    if (input.mode === "file" && !files.length && !input.modelUrl) throw new SubmissionError("Додайте файл або посилання на модель.");
    const attachments = await Promise.all(files.map(async (file) => { const bytes = Buffer.from(await file.arrayBuffer()); let metadata; try { metadata = validateAttachment(file.name, bytes); } catch (cause) { throw new SubmissionError(cause instanceof Error ? cause.message : "Перевірте вкладення."); } return { bytes, ...metadata, hash: createHash("sha256").update(bytes).digest("hex") }; }));
    const address = getTrustedClientAddress(request);
    const ipHash = createPrivacyHash("custom-request-ip", address || "unknown");
    const contentHash = customRequestContentHash(input, attachments.map((item) => item.hash));
    const previous = await prisma.customRequest.findUnique({ where: { submissionKey: input.submissionKey } });
    if (previous) {
      if (previous.ipHash !== ipHash || previous.contentHash !== contentHash) throw new SubmissionError("Цю заявку вже надіслано. Оновіть форму для нового запиту.",409);
      return NextResponse.json({ ok:true, publicId:previous.publicId }, {status:200});
    }
    for (const item of attachments) storedFiles.push(await savePrivateAttachment(item.bytes,item.extension));
    const result = await prisma.$transaction(async (tx) => {
      const duplicate = await tx.customRequest.findFirst({ where: { ipHash, contentHash, createdAt: { gte:new Date(Date.now() - 24 * 60 * 60 * 1000) } } });
      if (duplicate) return { record:duplicate, created:false };
      const recentCount = await tx.customRequest.count({ where: { ipHash, createdAt: { gte:new Date(Date.now() - 60 * 60 * 1000) } } });
      if (recentCount >= 5) throw new SubmissionError("Забагато заявок. Спробуйте через годину.",429);
      const record = await tx.customRequest.create({ data: { ...input, ipHash, contentHash, publicId:`ND-${randomUUID().replace(/-/g,"").slice(0,12).toUpperCase()}`, attachments: { create:attachments.map((item,index) => ({ fileName:storedFiles[index],originalName:item.originalName,size:item.bytes.length,mimeType:item.mimeType })) } } });
      return {record,created:true};
    });
    saved = result.created;
    if (!result.created) await Promise.all(storedFiles.map(deletePrivateAttachment));
    if (result.created) {
      // A single server event after persistence; analytics failure cannot fail submission.
      try {
        const excluded = address && await prisma.analyticsIpExclusion.findUnique({ where:{addressHash:hashAnalyticsIp(address)} });
        if (!excluded) await prisma.analyticsEvent.create({ data:{name:"Custom Request Submitted",path:"/custom",intent:"custom",location:input.mode,sessionId:/^[a-f0-9-]{36}$/.test(String(form.get("analyticsSessionId") ?? "")) ? String(form.get("analyticsSessionId")) : ""} });
      } catch { /* Analytics is optional. */ }
      await deliverCustomRequestNotification(result.record.publicId).catch(() => undefined);
    }
    return NextResponse.json({ ok:true,publicId:result.record.publicId },{status:result.created ? 201 : 200});
  } catch (error) {
    if (!saved) await Promise.all(storedFiles.map(deletePrivateAttachment));
    if (error instanceof SubmissionError) return NextResponse.json({error:error.message},{status:error.status});
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      // A racing duplicate is retried by the client with the same idempotency key.
      return NextResponse.json({error:"Заявка вже обробляється. Натисніть надіслати ще раз для підтвердження."},{status:409});
    }
    return NextResponse.json({error:"Не вдалося зберегти заявку. Дані залишились у формі — спробуйте ще раз."},{status:500});
  }
}
