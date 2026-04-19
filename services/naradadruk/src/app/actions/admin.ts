"use server";

import { timingSafeEqual } from "node:crypto";
import { redirect } from "next/navigation";
import { ProductStatus } from "@prisma/client";
import { z } from "zod";
import {
  clearAdminSession,
  createAdminSession,
  getAdminPassword,
  getAdminRoute,
  requireAdminSession,
} from "@/lib/auth";
import {
  createProduct,
  createProductImage,
  deleteCategory,
  deleteProduct,
  deleteProductImage,
  deleteVariant,
  saveCategory,
  saveSiteSettings,
  saveVariant,
  setCoverImage,
  updateProduct,
  updateProductImage,
} from "@/lib/data";
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
  status: z.nativeEnum(ProductStatus),
  isFeatured: z.boolean(),
  basePrice: z.number().int().nonnegative().nullable(),
  priceFrom: z.boolean(),
  leadTime: z.string().trim().max(120),
  materialNote: z.string().trim().max(160),
  deliveryNote: z.string().trim().max(160),
  paymentNote: z.string().trim().max(160),
  sortOrder: z.number().int(),
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

  const parsed = productUpdateSchema.safeParse({
    productId: parseOptionalInt(formData.get("productId")),
    title: String(formData.get("title") ?? ""),
    slug: String(formData.get("slug") ?? ""),
    categoryId: parseOptionalInt(formData.get("categoryId")),
    shortDescription: String(formData.get("shortDescription") ?? ""),
    fullDescription: String(formData.get("fullDescription") ?? ""),
    status: String(formData.get("status") ?? ProductStatus.draft),
    isFeatured: parseCheckbox(formData.get("isFeatured")),
    basePrice: parseOptionalInt(formData.get("basePrice")),
    priceFrom: parseCheckbox(formData.get("priceFrom")),
    leadTime: String(formData.get("leadTime") ?? ""),
    materialNote: String(formData.get("materialNote") ?? ""),
    deliveryNote: String(formData.get("deliveryNote") ?? ""),
    paymentNote: String(formData.get("paymentNote") ?? ""),
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
