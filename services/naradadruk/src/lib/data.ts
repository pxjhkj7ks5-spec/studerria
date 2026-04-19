import { ProductStatus, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { defaultTelegramUrl } from "@/lib/constants";
import { deleteUploadFile } from "@/lib/storage";
import { formatPrice, slugify } from "@/lib/utils";

const publicProductInclude = {
  category: true,
  variants: {
    orderBy: [{ sortOrder: "asc" }, { id: "asc" }],
  },
  images: {
    orderBy: [{ isCover: "desc" }, { sortOrder: "asc" }, { id: "asc" }],
  },
} satisfies Prisma.ProductInclude;

const adminProductInclude = publicProductInclude;

function resolveCoverImage<
  T extends {
    images: Array<{ urlPath: string; alt: string; isCover: boolean }>;
  },
>(product: T) {
  return product.images.find((image) => image.isCover) ?? product.images[0] ?? null;
}

export function resolveProductPrice(product: {
  basePrice: number | null;
  priceFrom: boolean;
  variants: Array<{ price: number }>;
}) {
  if (typeof product.basePrice === "number") {
    return product.priceFrom ? `від ${formatPrice(product.basePrice)}` : formatPrice(product.basePrice);
  }

  if (product.variants.length > 0) {
    const minimum = Math.min(...product.variants.map((variant) => variant.price));
    return product.variants.length > 1 ? `від ${formatPrice(minimum)}` : formatPrice(minimum);
  }

  return "Ціна за запитом";
}

async function generateUniqueSlug(
  model: "category" | "product",
  source: string,
  excludeId?: number,
) {
  const base = slugify(source);
  let candidate = base;
  let attempt = 1;

  while (true) {
    const existing =
      model === "category"
        ? await prisma.category.findUnique({ where: { slug: candidate } })
        : await prisma.product.findUnique({ where: { slug: candidate } });

    if (!existing || existing.id === excludeId) {
      return candidate;
    }

    attempt += 1;
    candidate = `${base}-${attempt}`;
  }
}

function getTelegramUrl(url?: string | null) {
  return (url || defaultTelegramUrl).trim() || defaultTelegramUrl;
}

export async function getSiteSettings() {
  const settings = await prisma.siteSetting.findUnique({ where: { id: 1 } });

  if (settings) {
    return settings;
  }

  return prisma.siteSetting.create({
    data: {
      id: 1,
      heroTitle: "3D друк, страйкбольні аксесуари та декор під ваш запит.",
      heroSubtitle:
        "Narada Druk збирає перевірені моделі та кастомні вироби в один каталог із прямим переходом у Telegram.",
      supportTitle: "Готові рішення і кастомні вироби в одному потоці.",
      supportBody:
        "Каталог допомагає швидко переглянути асортимент, а нестандартні замовлення домовляються напряму.",
      materialsNote: "PETG та інші практичні матеріали під задачу.",
      leadTimeNote: "Від кількох годин до 3 днів залежно від складності.",
      deliveryNote: "Доставка по Україні, самовивіз у Києві.",
      paymentNote: "Часткова або повна передплата на картку.",
      telegramUrl: defaultTelegramUrl,
      contactNote: "Надішліть приклад, розміри або ідею в Telegram, якщо потрібен індивідуальний виріб.",
    },
  });
}

export async function getVisibleCategories() {
  const [categories, counts] = await Promise.all([
    prisma.category.findMany({
      where: { isVisible: true },
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
    }),
    prisma.product.groupBy({
      by: ["categoryId"],
      where: { status: ProductStatus.published },
      _count: { _all: true },
    }),
  ]);

  const countMap = new Map(counts.map((entry) => [entry.categoryId, entry._count._all]));

  return categories.map((category) => ({
    ...category,
    publishedCount: countMap.get(category.id) ?? 0,
  }));
}

export async function getFeaturedProducts(limit = 6) {
  const products = await prisma.product.findMany({
    where: {
      status: ProductStatus.published,
      isFeatured: true,
      category: { isVisible: true },
    },
    include: publicProductInclude,
    take: limit,
    orderBy: [{ sortOrder: "asc" }, { updatedAt: "desc" }],
  });

  return products.map((product) => ({
    ...product,
    coverImage: resolveCoverImage(product),
    priceLabel: resolveProductPrice(product),
  }));
}

export async function getCatalogProducts(input?: { categorySlug?: string; search?: string }) {
  const search = input?.search?.trim();
  const products = await prisma.product.findMany({
    where: {
      status: ProductStatus.published,
      category: {
        isVisible: true,
        ...(input?.categorySlug ? { slug: input.categorySlug } : {}),
      },
      ...(search
        ? {
            OR: [
              { title: { contains: search } },
              { shortDescription: { contains: search } },
              { fullDescription: { contains: search } },
            ],
          }
        : {}),
    },
    include: publicProductInclude,
    orderBy: [{ isFeatured: "desc" }, { sortOrder: "asc" }, { updatedAt: "desc" }],
  });

  return products.map((product) => ({
    ...product,
    coverImage: resolveCoverImage(product),
    priceLabel: resolveProductPrice(product),
  }));
}

export async function getCategoryBySlug(slug: string) {
  const category = await prisma.category.findFirst({
    where: {
      slug,
      isVisible: true,
    },
  });

  return category;
}

export async function getProductBySlug(slug: string) {
  const product = await prisma.product.findFirst({
    where: {
      slug,
      status: ProductStatus.published,
      category: { isVisible: true },
    },
    include: publicProductInclude,
  });

  if (!product) {
    return null;
  }

  return {
    ...product,
    coverImage: resolveCoverImage(product),
    priceLabel: resolveProductPrice(product),
    telegramUrl: getTelegramUrl((await getSiteSettings()).telegramUrl),
  };
}

export async function getAdminDashboardData() {
  const [settings, categories, products] = await Promise.all([
    getSiteSettings(),
    prisma.category.findMany({
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
      include: {
        _count: {
          select: {
            products: true,
          },
        },
      },
    }),
    prisma.product.findMany({
      include: {
        category: true,
        images: {
          orderBy: [{ isCover: "desc" }, { sortOrder: "asc" }, { id: "asc" }],
        },
        variants: {
          orderBy: [{ sortOrder: "asc" }, { id: "asc" }],
        },
      },
      orderBy: [{ updatedAt: "desc" }],
    }),
  ]);

  return {
    settings,
    categories,
    products: products.map((product) => ({
      ...product,
      coverImage: resolveCoverImage(product),
      priceLabel: resolveProductPrice(product),
    })),
  };
}

export async function getAdminProductById(productId: number) {
  const [product, categories, settings] = await Promise.all([
    prisma.product.findUnique({
      where: { id: productId },
      include: adminProductInclude,
    }),
    prisma.category.findMany({
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
    }),
    getSiteSettings(),
  ]);

  if (!product) {
    return null;
  }

  return {
    product: {
      ...product,
      coverImage: resolveCoverImage(product),
      priceLabel: resolveProductPrice(product),
    },
    categories,
    settings,
  };
}

function hasProductPrice(basePrice: number | null, variants: Array<{ price: number }>) {
  return typeof basePrice === "number" || variants.length > 0;
}

async function assertProductCanPublish(productId: number, override?: { basePrice?: number | null }) {
  const product = await prisma.product.findUnique({
    where: { id: productId },
    include: {
      images: true,
      variants: true,
    },
  });

  if (!product) {
    throw new Error("Товар не знайдено.");
  }

  if (product.images.length === 0) {
    throw new Error("Для публікації потрібне хоча б одне зображення.");
  }

  const basePrice = override && Object.prototype.hasOwnProperty.call(override, "basePrice")
    ? override.basePrice ?? null
    : product.basePrice;

  if (!hasProductPrice(basePrice, product.variants)) {
    throw new Error("Для публікації потрібна базова ціна або хоча б один варіант.");
  }
}

export async function saveSiteSettings(input: {
  heroTitle: string;
  heroSubtitle: string;
  supportTitle: string;
  supportBody: string;
  materialsNote: string;
  leadTimeNote: string;
  deliveryNote: string;
  paymentNote: string;
  telegramUrl: string;
  contactNote: string;
}) {
  return prisma.siteSetting.upsert({
    where: { id: 1 },
    update: input,
    create: {
      id: 1,
      ...input,
    },
  });
}

export async function saveCategory(input: {
  categoryId?: number;
  name: string;
  slug?: string;
  description: string;
  sortOrder: number;
  isVisible: boolean;
}) {
  const slug = await generateUniqueSlug("category", input.slug || input.name, input.categoryId);

  if (input.categoryId) {
    return prisma.category.update({
      where: { id: input.categoryId },
      data: {
        name: input.name,
        slug,
        description: input.description,
        sortOrder: input.sortOrder,
        isVisible: input.isVisible,
      },
    });
  }

  return prisma.category.create({
    data: {
      name: input.name,
      slug,
      description: input.description,
      sortOrder: input.sortOrder,
      isVisible: input.isVisible,
    },
  });
}

export async function deleteCategory(categoryId: number) {
  const productsCount = await prisma.product.count({
    where: { categoryId },
  });

  if (productsCount > 0) {
    throw new Error("Спершу перемістіть або видаліть товари з цієї категорії.");
  }

  await prisma.category.delete({
    where: { id: categoryId },
  });
}

export async function createProduct(input: {
  title: string;
  categoryId: number;
}) {
  const slug = await generateUniqueSlug("product", input.title);

  return prisma.product.create({
    data: {
      title: input.title,
      slug,
      categoryId: input.categoryId,
      status: ProductStatus.draft,
    },
  });
}

export async function updateProduct(input: {
  productId: number;
  title: string;
  slug?: string;
  categoryId: number;
  shortDescription: string;
  fullDescription: string;
  status: ProductStatus;
  isFeatured: boolean;
  basePrice: number | null;
  priceFrom: boolean;
  leadTime: string;
  materialNote: string;
  deliveryNote: string;
  paymentNote: string;
  sortOrder: number;
}) {
  const slug = await generateUniqueSlug("product", input.slug || input.title, input.productId);

  if (input.status === ProductStatus.published) {
    await assertProductCanPublish(input.productId, { basePrice: input.basePrice });
  }

  return prisma.product.update({
    where: { id: input.productId },
    data: {
      title: input.title,
      slug,
      categoryId: input.categoryId,
      shortDescription: input.shortDescription,
      fullDescription: input.fullDescription,
      status: input.status,
      isFeatured: input.isFeatured,
      basePrice: input.basePrice,
      priceFrom: input.priceFrom,
      leadTime: input.leadTime,
      materialNote: input.materialNote,
      deliveryNote: input.deliveryNote,
      paymentNote: input.paymentNote,
      sortOrder: input.sortOrder,
    },
  });
}

export async function deleteProduct(productId: number) {
  const images = await prisma.productImage.findMany({
    where: { productId },
  });

  await prisma.product.delete({
    where: { id: productId },
  });

  await Promise.all(images.map((image) => deleteUploadFile(image.fileName)));
}

export async function saveVariant(input: {
  variantId?: number;
  productId: number;
  label: string;
  price: number;
  description: string;
  sortOrder: number;
}) {
  if (input.variantId) {
    return prisma.productVariant.update({
      where: { id: input.variantId },
      data: {
        label: input.label,
        price: input.price,
        description: input.description,
        sortOrder: input.sortOrder,
      },
    });
  }

  return prisma.productVariant.create({
    data: {
      productId: input.productId,
      label: input.label,
      price: input.price,
      description: input.description,
      sortOrder: input.sortOrder,
    },
  });
}

export async function deleteVariant(variantId: number) {
  await prisma.productVariant.delete({
    where: { id: variantId },
  });
}

export async function createProductImage(input: {
  productId: number;
  fileName: string;
  urlPath: string;
  alt: string;
  sortOrder: number;
}) {
  const existingImagesCount = await prisma.productImage.count({
    where: { productId: input.productId },
  });

  return prisma.productImage.create({
    data: {
      productId: input.productId,
      fileName: input.fileName,
      urlPath: input.urlPath,
      alt: input.alt,
      sortOrder: input.sortOrder,
      isCover: existingImagesCount === 0,
    },
  });
}

export async function updateProductImage(input: {
  imageId: number;
  alt: string;
  sortOrder: number;
}) {
  return prisma.productImage.update({
    where: { id: input.imageId },
    data: {
      alt: input.alt,
      sortOrder: input.sortOrder,
    },
  });
}

export async function setCoverImage(imageId: number) {
  const image = await prisma.productImage.findUnique({
    where: { id: imageId },
  });

  if (!image) {
    throw new Error("Зображення не знайдено.");
  }

  await prisma.$transaction([
    prisma.productImage.updateMany({
      where: { productId: image.productId },
      data: { isCover: false },
    }),
    prisma.productImage.update({
      where: { id: imageId },
      data: { isCover: true },
    }),
  ]);
}

export async function deleteProductImage(imageId: number) {
  const image = await prisma.productImage.findUnique({
    where: { id: imageId },
  });

  if (!image) {
    return;
  }

  await prisma.productImage.delete({
    where: { id: imageId },
  });

  await deleteUploadFile(image.fileName);

  if (image.isCover) {
    const fallback = await prisma.productImage.findFirst({
      where: { productId: image.productId },
      orderBy: [{ sortOrder: "asc" }, { id: "asc" }],
    });

    if (fallback) {
      await prisma.productImage.update({
        where: { id: fallback.id },
        data: { isCover: true },
      });
    }
  }
}
