"use server";

import { timingSafeEqual } from "node:crypto";
import { redirect } from "next/navigation";
import { OrderStatus, Prisma, ProductStatus, ReviewStatus } from "@prisma/client";
import { z } from "zod";
import {
  clearAdminSession,
  createAdminSession,
  getAdminPassword,
  getAdminRoute,
  requireAdminSession,
} from "@/lib/auth";
import {
  createAnalyticsIpExclusion,
  createProduct,
  createProductImage,
  deleteAnalyticsIpExclusion,
  deleteCategory,
  deleteProduct,
  deleteProductImage,
  deleteReview,
  deleteUnusedPromoCode,
  deleteVariant,
  permanentlyDeleteOrder,
  saveCategory,
  saveSiteSettings,
  savePromoCode,
  saveVariant,
  setCoverImage,
  setReviewStatus,
  updateProduct,
  updateProductImage,
  updateOrderStatus,
  addOrderComment,
} from "@/lib/data";
import { analyticsIpHint, hashAnalyticsIp, normalizeIpAddress } from "@/lib/analytics-ip";
import { saveProductImage } from "@/lib/storage";
import { parseCheckbox, parseOptionalInt } from "@/lib/utils";

export type ActionState = {
  error?: string;
};

const loginSchema = z.object({
  password: z.string().min(1),
});

const categorySchema = z.object({
  categoryId: z.number().int().positive().optional(),
  name: z.string().trim().min(2, "Назва категорії занадто коротка."),
  slug: z.string().trim().optional(),
  description: z.string().trim().max(240, "Опис категорії занадто довгий."),
  sortOrder: z.number().int(),
  isVisible: z.boolean(),
});

const settingsSchema = z.object({
  heroTitle: z.string().trim().min(8, "Hero title занадто короткий."),
  heroSubtitle: z.string().trim().min(20, "Hero subtitle занадто короткий."),
  supportTitle: z.string().trim().min(4, "Support title занадто короткий."),
  supportBody: z.string().trim().min(10, "Support body занадто короткий."),
  materialsNote: z.string().trim().min(4, "Вкажіть матеріали."),
  leadTimeNote: z.string().trim().min(4, "Вкажіть терміни."),
  deliveryNote: z.string().trim().min(4, "Вкажіть доставку."),
  paymentNote: z.string().trim().min(4, "Вкажіть оплату."),
  telegramUrl: z.string().trim().url("Telegram URL некоректний."),
  contactNote: z.string().trim().min(6, "Contact note занадто короткий."),
});

const productCreateSchema = z.object({
  title: z.string().trim().min(3, "Назва товару занадто коротка."),
  categoryId: z.number().int().positive("Оберіть категорію."),
});

const productUpdateSchema = z.object({
  productId: z.number().int().positive(),
  title: z.string().trim().min(3, "Назва товару занадто коротка."),
  slug: z.string().trim().optional(),
  categoryId: z.number().int().positive("Оберіть категорію."),
  shortDescription: z.string().trim().min(8, "Короткий опис занадто короткий."),
  fullDescription: z.string().trim().min(20, "Повний опис занадто короткий."),
  telegramDescription: z.string().trim().max(700),
  useCaseNote: z.string().trim().max(2000),
  benefitsNote: z.string().trim().max(3000),
  specificationsNote: z.string().trim().max(3000),
  compatibilityNote: z.string().trim().max(2000),
  packageContentsNote: z.string().trim().max(2000),
  status: z.nativeEnum(ProductStatus),
  isFeatured: z.boolean(),
  basePrice: z.number().int().nonnegative().nullable(),
  priceFrom: z.boolean(),
  saleEnabled: z.boolean(),
  salePrice: z.number().int().nonnegative().nullable(),
  salePercent: z.number().int().min(1).max(99).nullable(),
  saleStartsAt: z.date().nullable(),
  saleEndsAt: z.date().nullable(),
  leadTime: z.string().trim().max(120),
  materialNote: z.string().trim().max(160),
  deliveryNote: z.string().trim().max(160),
  paymentNote: z.string().trim().max(160),
  printWeightGrams: z.number().int().positive().max(1_000_000).nullable(),
  sourceModelUrl: z.string().trim().max(1000),
  sourceModelAuthor: z.string().trim().max(300),
  sourceModelLicense: z.string().trim().max(300),
  sourceLicenseChecked: z.boolean(),
  sortOrder: z.number().int(),
}).superRefine((value, context) => {
  if (value.saleEnabled && value.salePrice === null && value.salePercent === null) context.addIssue({ code: "custom", path: ["salePrice"], message: "Для акції вкажіть акційну ціну або відсоток." });
  if (value.salePrice !== null && value.salePercent !== null) context.addIssue({ code: "custom", path: ["salePercent"], message: "Оберіть акційну ціну або відсоток, не обидва одночасно." });
  if (value.salePrice !== null && (value.basePrice === null || value.salePrice >= value.basePrice)) context.addIssue({ code: "custom", path: ["salePrice"], message: "Акційна ціна має бути нижчою за базову." });
  if (value.saleStartsAt && value.saleEndsAt && value.saleEndsAt <= value.saleStartsAt) context.addIssue({ code: "custom", path: ["saleEndsAt"], message: "Завершення акції має бути пізніше за початок." });
});

const variantSchema = z.object({
  productId: z.number().int().positive(),
  variantId: z.number().int().positive().optional(),
  label: z.string().trim().min(2, "Назва варіанту занадто коротка."),
  price: z.number().int().nonnegative("Ціна має бути додатною."),
  description: z.string().trim().max(160),
  sortOrder: z.number().int(),
});

const imageMetaSchema = z.object({
  productId: z.number().int().positive(),
  imageId: z.number().int().positive().optional(),
  alt: z.string().trim().max(140),
  sortOrder: z.number().int(),
});

const promoCodeSchema = z.object({
  id: z.number().int().positive().optional(),
  code: z.string().trim().regex(/^[A-Za-zА-Яа-яІіЇїЄєҐґ0-9_-]{3,32}$/u, "Код: 3–32 українські або латинські літери, цифри, _ чи -."),
  type: z.enum(["percentage", "fixed"]),
  value: z.number().int().positive("Знижка має бути більшою за нуль."),
  usageLimit: z.number().int().positive().nullable(),
  expiresAt: z.date().nullable(),
  enabled: z.boolean(),
}).superRefine((value, context) => {
  if (value.type === "percentage" && value.value > 99) context.addIssue({ code: "custom", path: ["value"], message: "Відсоткова знижка має бути від 1% до 99%." });
});

function compareSecret(left: string, right: string) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
}

function messagePath(path: string, key: "ok" | "error", message: string) {
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}${key}=${encodeURIComponent(message)}`;
}

function adminProductPath(productId: number) {
  return `${getAdminRoute()}/products/${productId}`;
}

export async function loginAction(
  _previousState: ActionState,
  formData: FormData,
): Promise<ActionState> {
  const parsed = loginSchema.safeParse({
    password: String(formData.get("password") ?? ""),
  });

  if (!parsed.success || !compareSecret(parsed.data.password, getAdminPassword())) {
    return { error: "Невірний пароль." };
  }

  await createAdminSession();
  redirect(messagePath(getAdminRoute(), "ok", "Вхід підтверджено."));
}

export async function logoutAction() {
  await clearAdminSession();
  redirect(getAdminRoute());
}

export async function saveSettingsAction(formData: FormData) {
  await requireAdminSession();

  const parsed = settingsSchema.safeParse({
    heroTitle: String(formData.get("heroTitle") ?? ""),
    heroSubtitle: String(formData.get("heroSubtitle") ?? ""),
    supportTitle: String(formData.get("supportTitle") ?? ""),
    supportBody: String(formData.get("supportBody") ?? ""),
    materialsNote: String(formData.get("materialsNote") ?? ""),
    leadTimeNote: String(formData.get("leadTimeNote") ?? ""),
    deliveryNote: String(formData.get("deliveryNote") ?? ""),
    paymentNote: String(formData.get("paymentNote") ?? ""),
    telegramUrl: String(formData.get("telegramUrl") ?? ""),
    contactNote: String(formData.get("contactNote") ?? ""),
  });

  if (!parsed.success) {
    redirect(messagePath(getAdminRoute(), "error", parsed.error.issues[0]?.message ?? "Не вдалося зберегти storefront."));
  }

  await saveSiteSettings(parsed.data);
  redirect(messagePath(getAdminRoute(), "ok", "Storefront збережено."));
}

export async function addAnalyticsIpExclusionAction(formData: FormData) {
  await requireAdminSession();
  const address = normalizeIpAddress(String(formData.get("address") ?? ""));
  const label = String(formData.get("label") ?? "").trim().slice(0, 80);
  const returnPath = getAdminRoute();
  const withAnchor = (path: string) => `${path}#analytics-exclusions`;
  if (!address) {
    redirect(withAnchor(messagePath(returnPath, "error", "Введіть коректну IPv4 або IPv6 адресу.")));
  }

  try {
    await createAnalyticsIpExclusion({
      addressHash: hashAnalyticsIp(address),
      addressHint: analyticsIpHint(address),
      label,
    });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      redirect(withAnchor(messagePath(returnPath, "error", "Ця IP-адреса вже виключена з аналітики.")));
    }
    console.error("[admin] failed to add analytics IP exclusion", error);
    redirect(withAnchor(messagePath(returnPath, "error", "Не вдалося додати IP-адресу. Спробуйте ще раз.")));
  }
  redirect(withAnchor(messagePath(returnPath, "ok", "IP-адресу виключено з нових подій аналітики.")));
}

export async function deleteAnalyticsIpExclusionAction(formData: FormData) {
  await requireAdminSession();
  const exclusionId = parseOptionalInt(formData.get("exclusionId"));
  const returnPath = getAdminRoute();
  const withAnchor = (path: string) => `${path}#analytics-exclusions`;
  if (!exclusionId) {
    redirect(withAnchor(messagePath(returnPath, "error", "Запис виключення не знайдено.")));
  }
  const deleted = await deleteAnalyticsIpExclusion(exclusionId);
  redirect(withAnchor(messagePath(returnPath, deleted.count ? "ok" : "error", deleted.count ? "IP-виключення видалено. Нові події з цієї адреси знову враховуватимуться." : "IP-виключення вже видалено або не знайдено.")));
}

export async function saveCategoryAction(formData: FormData) {
  await requireAdminSession();

  const parsed = categorySchema.safeParse({
    categoryId: parseOptionalInt(formData.get("categoryId")) ?? undefined,
    name: String(formData.get("name") ?? ""),
    slug: String(formData.get("slug") ?? ""),
    description: String(formData.get("description") ?? ""),
    sortOrder: parseOptionalInt(formData.get("sortOrder")) ?? 0,
    isVisible: parseCheckbox(formData.get("isVisible")),
  });

  if (!parsed.success) {
    redirect(messagePath(getAdminRoute(), "error", parsed.error.issues[0]?.message ?? "Категорію не збережено."));
  }

  await saveCategory(parsed.data);
  redirect(messagePath(getAdminRoute(), "ok", "Категорію збережено."));
}

export async function deleteCategoryAction(formData: FormData) {
  await requireAdminSession();

  const categoryId = parseOptionalInt(formData.get("categoryId"));

  if (!categoryId) {
    redirect(messagePath(getAdminRoute(), "error", "Категорію не знайдено."));
  }

  try {
    await deleteCategory(categoryId);
    redirect(messagePath(getAdminRoute(), "ok", "Категорію видалено."));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Категорію не вдалося видалити.";
    redirect(messagePath(getAdminRoute(), "error", message));
  }
}

export async function createProductAction(formData: FormData) {
  await requireAdminSession();

  const parsed = productCreateSchema.safeParse({
    title: String(formData.get("title") ?? ""),
    categoryId: parseOptionalInt(formData.get("categoryId")),
  });

  if (!parsed.success) {
    redirect(messagePath(getAdminRoute(), "error", parsed.error.issues[0]?.message ?? "Товар не створено."));
  }

  const product = await createProduct(parsed.data);
  redirect(messagePath(adminProductPath(product.id), "ok", "Чернетку створено."));
}

export async function updateProductAction(formData: FormData) {
  await requireAdminSession();

  const saleStartsAt = String(formData.get("saleStartsAt") ?? "").trim();
  const saleEndsAt = String(formData.get("saleEndsAt") ?? "").trim();
  const parsed = productUpdateSchema.safeParse({
    productId: parseOptionalInt(formData.get("productId")),
    title: String(formData.get("title") ?? ""),
    slug: String(formData.get("slug") ?? ""),
    categoryId: parseOptionalInt(formData.get("categoryId")),
    shortDescription: String(formData.get("shortDescription") ?? ""),
    fullDescription: String(formData.get("fullDescription") ?? ""),
    telegramDescription: String(formData.get("telegramDescription") ?? ""),
    useCaseNote: String(formData.get("useCaseNote") ?? ""),
    benefitsNote: String(formData.get("benefitsNote") ?? ""),
    specificationsNote: String(formData.get("specificationsNote") ?? ""),
    compatibilityNote: String(formData.get("compatibilityNote") ?? ""),
    packageContentsNote: String(formData.get("packageContentsNote") ?? ""),
    status: String(formData.get("status") ?? ProductStatus.draft),
    isFeatured: parseCheckbox(formData.get("isFeatured")),
    basePrice: parseOptionalInt(formData.get("basePrice")),
    priceFrom: parseCheckbox(formData.get("priceFrom")),
    saleEnabled: parseCheckbox(formData.get("saleEnabled")),
    salePrice: parseOptionalInt(formData.get("salePrice")),
    salePercent: parseOptionalInt(formData.get("salePercent")),
    saleStartsAt: saleStartsAt ? new Date(saleStartsAt) : null,
    saleEndsAt: saleEndsAt ? new Date(saleEndsAt) : null,
    leadTime: String(formData.get("leadTime") ?? ""),
    materialNote: String(formData.get("materialNote") ?? ""),
    deliveryNote: String(formData.get("deliveryNote") ?? ""),
    paymentNote: String(formData.get("paymentNote") ?? ""),
    printWeightGrams: parseOptionalInt(formData.get("printWeightGrams")),
    sourceModelUrl: String(formData.get("sourceModelUrl") ?? ""),
    sourceModelAuthor: String(formData.get("sourceModelAuthor") ?? ""),
    sourceModelLicense: String(formData.get("sourceModelLicense") ?? ""),
    sourceLicenseChecked: parseCheckbox(formData.get("sourceLicenseChecked")),
    sortOrder: parseOptionalInt(formData.get("sortOrder")) ?? 0,
  });

  if (!parsed.success) {
    const productId = parseOptionalInt(formData.get("productId")) ?? 0;
    redirect(messagePath(adminProductPath(productId), "error", parsed.error.issues[0]?.message ?? "Товар не збережено."));
  }

  try {
    const product = await updateProduct(parsed.data);
    redirect(messagePath(adminProductPath(product.id), "ok", "Товар оновлено."));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Товар не збережено.";
    redirect(messagePath(adminProductPath(parsed.data.productId), "error", message));
  }
}

export async function deleteProductAction(formData: FormData) {
  await requireAdminSession();

  const productId = parseOptionalInt(formData.get("productId"));

  if (!productId) {
    redirect(messagePath(getAdminRoute(), "error", "Товар не знайдено."));
  }

  await deleteProduct(productId);
  redirect(messagePath(getAdminRoute(), "ok", "Товар видалено."));
}

export async function saveVariantAction(formData: FormData) {
  await requireAdminSession();

  const parsed = variantSchema.safeParse({
    productId: parseOptionalInt(formData.get("productId")),
    variantId: parseOptionalInt(formData.get("variantId")) ?? undefined,
    label: String(formData.get("label") ?? ""),
    price: parseOptionalInt(formData.get("price")),
    description: String(formData.get("description") ?? ""),
    sortOrder: parseOptionalInt(formData.get("sortOrder")) ?? 0,
  });

  if (!parsed.success) {
    const productId = parseOptionalInt(formData.get("productId")) ?? 0;
    redirect(messagePath(adminProductPath(productId), "error", parsed.error.issues[0]?.message ?? "Варіант не збережено."));
  }

  await saveVariant(parsed.data);
  redirect(messagePath(adminProductPath(parsed.data.productId), "ok", "Варіант збережено."));
}

export async function deleteVariantAction(formData: FormData) {
  await requireAdminSession();

  const productId = parseOptionalInt(formData.get("productId"));
  const variantId = parseOptionalInt(formData.get("variantId"));

  if (!productId || !variantId) {
    redirect(messagePath(getAdminRoute(), "error", "Варіант не знайдено."));
  }

  await deleteVariant(variantId);
  redirect(messagePath(adminProductPath(productId), "ok", "Варіант видалено."));
}

export async function uploadProductImageAction(formData: FormData) {
  await requireAdminSession();

  const parsed = imageMetaSchema.safeParse({
    productId: parseOptionalInt(formData.get("productId")),
    alt: String(formData.get("alt") ?? ""),
    sortOrder: parseOptionalInt(formData.get("sortOrder")) ?? 0,
  });

  if (!parsed.success) {
    const productId = parseOptionalInt(formData.get("productId")) ?? 0;
    redirect(messagePath(adminProductPath(productId), "error", parsed.error.issues[0]?.message ?? "Зображення не завантажено."));
  }

  const file = formData.get("image");

  if (!(file instanceof File) || file.size === 0) {
    redirect(messagePath(adminProductPath(parsed.data.productId), "error", "Оберіть файл зображення."));
  }

  try {
    const stored = await saveProductImage(file, `${parsed.data.productId}-${Date.now()}`);
    await createProductImage({
      productId: parsed.data.productId,
      fileName: stored.fileName,
      urlPath: stored.urlPath,
      alt: parsed.data.alt,
      sortOrder: parsed.data.sortOrder,
    });
    redirect(messagePath(adminProductPath(parsed.data.productId), "ok", "Зображення додано."));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Зображення не завантажено.";
    redirect(messagePath(adminProductPath(parsed.data.productId), "error", message));
  }
}

export async function updateProductImageAction(formData: FormData) {
  await requireAdminSession();

  const parsed = imageMetaSchema.safeParse({
    productId: parseOptionalInt(formData.get("productId")),
    imageId: parseOptionalInt(formData.get("imageId")) ?? undefined,
    alt: String(formData.get("alt") ?? ""),
    sortOrder: parseOptionalInt(formData.get("sortOrder")) ?? 0,
  });

  if (!parsed.success || !parsed.data.imageId) {
    const productId = parseOptionalInt(formData.get("productId")) ?? 0;
    redirect(messagePath(adminProductPath(productId), "error", "Зображення не оновлено."));
  }

  await updateProductImage({
    imageId: parsed.data.imageId,
    alt: parsed.data.alt,
    sortOrder: parsed.data.sortOrder,
  });
  redirect(messagePath(adminProductPath(parsed.data.productId), "ok", "Параметри зображення оновлено."));
}

export async function setCoverImageAction(formData: FormData) {
  await requireAdminSession();

  const productId = parseOptionalInt(formData.get("productId"));
  const imageId = parseOptionalInt(formData.get("imageId"));

  if (!productId || !imageId) {
    redirect(messagePath(getAdminRoute(), "error", "Зображення не знайдено."));
  }

  await setCoverImage(imageId);
  redirect(messagePath(adminProductPath(productId), "ok", "Обкладинку оновлено."));
}

export async function deleteProductImageAction(formData: FormData) {
  await requireAdminSession();

  const productId = parseOptionalInt(formData.get("productId"));
  const imageId = parseOptionalInt(formData.get("imageId"));

  if (!productId || !imageId) {
    redirect(messagePath(getAdminRoute(), "error", "Зображення не знайдено."));
  }

  await deleteProductImage(imageId);
  redirect(messagePath(adminProductPath(productId), "ok", "Зображення видалено."));
}

export async function moderateReviewAction(formData: FormData) {
  await requireAdminSession();
  const reviewId = parseOptionalInt(formData.get("reviewId"));
  const status = String(formData.get("status") ?? "");
  const isModeratedStatus = status === ReviewStatus.approved || status === ReviewStatus.rejected;
  if (!reviewId || !isModeratedStatus) {
    redirect(messagePath(`${getAdminRoute()}/reviews`, "error", "Не вдалося змінити статус відгуку."));
  }
  await setReviewStatus(reviewId, status);
  redirect(messagePath(`${getAdminRoute()}/reviews/${reviewId}`, "ok", status === ReviewStatus.approved ? "Відгук опубліковано." : "Відгук приховано."));
}

export async function deleteReviewAction(formData: FormData) {
  await requireAdminSession();
  const reviewId = parseOptionalInt(formData.get("reviewId"));
  if (!reviewId) {
    redirect(messagePath(`${getAdminRoute()}/reviews`, "error", "Відгук не знайдено."));
  }
  await deleteReview(reviewId);
  redirect(messagePath(`${getAdminRoute()}/reviews`, "ok", "Відгук і його фото видалено."));
}

export async function savePromoCodeAction(formData: FormData) {
  await requireAdminSession();
  const expiry = String(formData.get("expiresAt") ?? "").trim();
  const parsed = promoCodeSchema.safeParse({
    id: parseOptionalInt(formData.get("id")) ?? undefined,
    code: String(formData.get("code") ?? ""),
    type: String(formData.get("type") ?? "percentage"),
    value: parseOptionalInt(formData.get("value")),
    usageLimit: parseOptionalInt(formData.get("usageLimit")),
    expiresAt: expiry ? new Date(expiry) : null,
    enabled: parseCheckbox(formData.get("enabled")),
  });
  const base = `${getAdminRoute()}/promo-codes`;
  const returnPath = parsed.success && parsed.data.id ? `${base}/${parsed.data.id}` : base;
  if (!parsed.success || (expiry && Number.isNaN(parsed.data.expiresAt?.getTime()))) {
    redirect(messagePath(returnPath, "error", parsed.success ? "Некоректна дата завершення." : parsed.error.issues[0]?.message ?? "Перевірте промокод."));
  }
  let promo: Awaited<ReturnType<typeof savePromoCode>>;
  try {
    promo = await savePromoCode(parsed.data);
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      redirect(messagePath(returnPath, "error", `Промокод «${parsed.data.code.trim()}» уже існує.`));
    }
    console.error("[admin] failed to save promo code", error);
    redirect(messagePath(returnPath, "error", "Не вдалося зберегти промокод через помилку сервера. Спробуйте ще раз."));
  }
  redirect(messagePath(`${base}/${promo.id}`, "ok", "Промокод збережено."));
}

export async function deletePromoCodeAction(formData: FormData) {
  await requireAdminSession();
  const promoId = parseOptionalInt(formData.get("promoId"));
  const base = `${getAdminRoute()}/promo-codes`;
  if (!promoId) {
    redirect(messagePath(base, "error", "Промокод не знайдено."));
  }
  if (formData.get("confirmDelete") !== "yes") {
    redirect(messagePath(`${base}/${promoId}`, "error", "Підтвердьте видалення промокоду."));
  }

  let result: Awaited<ReturnType<typeof deleteUnusedPromoCode>>;
  try {
    result = await deleteUnusedPromoCode(promoId);
  } catch (error) {
    console.error("[admin] failed to delete promo code", error);
    redirect(messagePath(`${base}/${promoId}`, "error", "Не вдалося видалити промокод через помилку сервера. Спробуйте ще раз."));
  }
  if (result === "used") {
    redirect(messagePath(`${base}/${promoId}`, "error", "Цей промокод уже використано. Його не можна видалити — вимкніть код, щоб зберегти історію замовлень."));
  }
  if (result === "missing") {
    redirect(messagePath(base, "error", "Промокод уже видалено або не знайдено."));
  }
  redirect(messagePath(base, "ok", "Невикористаний промокод видалено."));
}

export async function updateOrderStatusAction(formData: FormData) {
  await requireAdminSession();
  const publicId = String(formData.get("publicId") ?? "");
  const status = String(formData.get("status") ?? "");
  const orderStatus = status === OrderStatus.new
    || status === OrderStatus.accepted
    || status === OrderStatus.shipped
    || status === OrderStatus.closed
    ? status
    : null;
  if (!/^[0-9a-f-]{36}$/i.test(publicId) || !orderStatus) redirect(getAdminRoute());
  await updateOrderStatus(publicId, orderStatus);
  redirect(messagePath(`${getAdminRoute()}/orders/${publicId}`, "ok", "Статус замовлення оновлено."));
}

export async function addOrderCommentAction(formData: FormData) {
  await requireAdminSession();
  const publicId = String(formData.get("publicId") ?? "");
  const comment = String(formData.get("comment") ?? "").trim().slice(0, 1000);
  if (!/^[0-9a-f-]{36}$/i.test(publicId) || comment.length < 2) redirect(messagePath(`${getAdminRoute()}/orders/${publicId}`, "error", "Введіть внутрішній коментар."));
  await addOrderComment(publicId, comment);
  redirect(messagePath(`${getAdminRoute()}/orders/${publicId}`, "ok", "Внутрішній коментар додано."));
}

export async function permanentlyDeleteOrderAction(formData: FormData) {
  await requireAdminSession();
  const publicId = String(formData.get("publicId") ?? "");
  const confirmation = String(formData.get("confirmation") ?? "").trim().toUpperCase();
  const ordersPath = `${getAdminRoute()}/orders`;
  if (!/^[0-9a-f-]{36}$/i.test(publicId)) {
    redirect(messagePath(ordersPath, "error", "Замовлення не знайдено."));
  }
  const expected = publicId.slice(0, 8).toUpperCase();
  if (confirmation !== expected) {
    redirect(messagePath(`${ordersPath}/${publicId}`, "error", `Для видалення введіть код ${expected}.`));
  }

  let result: Awaited<ReturnType<typeof permanentlyDeleteOrder>>;
  try {
    result = await permanentlyDeleteOrder(publicId);
  } catch (error) {
    console.error("[admin] failed to permanently delete order", error);
    redirect(messagePath(`${ordersPath}/${publicId}`, "error", "Не вдалося видалити замовлення. Спробуйте ще раз."));
  }
  if (result === "missing") {
    redirect(messagePath(ordersPath, "error", "Замовлення вже видалено або не знайдено."));
  }
  redirect(messagePath(ordersPath, "ok", "Замовлення видалено назавжди. Статистику та використання промокоду оновлено."));
}
