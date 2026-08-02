import { createHash, randomUUID } from "node:crypto";
import { Prisma } from "@prisma/client";
import { NextResponse } from "next/server";
import { createPrivacyHash } from "@/lib/auth";
import { prisma } from "@/lib/prisma";
import { getClientAddress, reviewInputSchema } from "@/lib/review-validation";
import { deleteUploadFile, saveReviewImage, type StoredUpload } from "@/lib/storage";
import { notifyOwnerAboutReview } from "@/lib/telegram-reviews";

export const runtime = "nodejs";

const rateWindowMs = 24 * 60 * 60 * 1000;
const duplicateWindowMs = 7 * 24 * 60 * 60 * 1000;
const maximumPhotos = 4;
const maximumTotalBytes = 12 * 1024 * 1024;

class ReviewSubmissionError extends Error {
  constructor(message: string, readonly status = 400) {
    super(message);
  }
}

export async function POST(request: Request) {
  const contentLength = Number(request.headers.get("content-length") || "0");
  if (Number.isFinite(contentLength) && contentLength > 14 * 1024 * 1024) {
    return NextResponse.json({ error: "Загальний розмір форми завеликий." }, { status: 413 });
  }
  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return NextResponse.json({ error: "Не вдалося прочитати форму відгуку." }, { status: 400 });
  }

  if (String(formData.get("website") ?? "").trim()) {
    return NextResponse.json({ ok: true }, { status: 201 });
  }

  const parsed = reviewInputSchema.safeParse({
    displayName: String(formData.get("displayName") ?? ""),
    isAnonymous: String(formData.get("isAnonymous") ?? "") === "true",
    body: String(formData.get("body") ?? ""),
  });
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues[0]?.message ?? "Перевірте поля відгуку." },
      { status: 400 },
    );
  }

  const photos = formData.getAll("photos").filter(
    (entry): entry is File => entry instanceof File && entry.size > 0,
  );
  if (photos.length > maximumPhotos) {
    return NextResponse.json({ error: "Можна додати не більше чотирьох фото." }, { status: 400 });
  }
  if (photos.reduce((sum, photo) => sum + photo.size, 0) > maximumTotalBytes) {
    return NextResponse.json({ error: "Загальний розмір фото не може перевищувати 12 MB." }, { status: 400 });
  }

  const orderPublicId = String(formData.get("orderPublicId") ?? "").trim();
  const reviewOrder = orderPublicId
    ? await prisma.order.findUnique({
        where: { publicId: orderPublicId },
        select: { id: true, review: { select: { id: true } } },
      })
    : null;
  if (orderPublicId && !reviewOrder) {
    return NextResponse.json({ error: "Посилання на замовлення недійсне." }, { status: 400 });
  }
  if (reviewOrder?.review) {
    return NextResponse.json({ error: "Відгук за цим замовленням уже надіслано." }, { status: 409 });
  }

  const addressHash = createPrivacyHash("review-ip", getClientAddress(request));
  const contentHash = createHash("sha256")
    .update(parsed.data.body.toLocaleLowerCase("uk-UA").replace(/\s+/g, " "))
    .digest("base64url");
  const rateStart = new Date(Date.now() - rateWindowMs);
  const duplicateStart = new Date(Date.now() - duplicateWindowMs);
  const [recentCount, duplicate] = await Promise.all([
    prisma.review.count({ where: { ipHash: addressHash, createdAt: { gte: rateStart } } }),
    prisma.review.findFirst({
      where: { ipHash: addressHash, contentHash, createdAt: { gte: duplicateStart } },
      select: { id: true },
    }),
  ]);
  if (recentCount >= 3) {
    return NextResponse.json(
      { error: "З цієї мережі вже надіслано забагато відгуків. Спробуйте пізніше." },
      { status: 429 },
    );
  }
  if (duplicate) {
    return NextResponse.json({ error: "Такий відгук уже надіслано на модерацію." }, { status: 409 });
  }

  const stored: StoredUpload[] = [];
  try {
    for (const [index, photo] of photos.entries()) {
      stored.push(await saveReviewImage(photo, `review-${randomUUID()}-${index + 1}`));
    }

    const review = await prisma.review.create({
      data: {
        displayName: parsed.data.isAnonymous ? "" : parsed.data.displayName,
        isAnonymous: parsed.data.isAnonymous || !parsed.data.displayName,
        body: parsed.data.body,
        ipHash: addressHash,
        contentHash,
        orderId: reviewOrder?.id ?? null,
        verifiedPurchase: Boolean(reviewOrder),
        images: {
          create: stored.map((image, index) => ({
            fileName: image.fileName,
            urlPath: image.urlPath,
            alt: `Фото до відгуку ${index + 1}`,
            sortOrder: (index + 1) * 10,
          })),
        },
      },
      include: {
        images: { orderBy: { sortOrder: "asc" } },
        order: { select: { publicId: true } },
      },
    });

    const notification = await notifyOwnerAboutReview(review);
    await prisma.review.update({
      where: { id: review.id },
      data: {
        notificationStatus: notification.status,
        notificationError: notification.error,
        telegramMessageId: notification.messageId,
      },
    }).catch((error) => console.error("[reviews] notification status update failed", error));

    return NextResponse.json({ ok: true }, { status: 201 });
  } catch (error) {
    await Promise.all(stored.map((image) => deleteUploadFile(image.fileName)));
    if (error instanceof ReviewSubmissionError) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      return NextResponse.json({ error: "Відгук за цим замовленням уже надіслано." }, { status: 409 });
    }
    const message = error instanceof Error && /фото|JPG|PNG|WebP|MB/.test(error.message)
      ? error.message
      : "Не вдалося надіслати відгук. Спробуйте ще раз.";
    console.error("[reviews] submission failed", error);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
