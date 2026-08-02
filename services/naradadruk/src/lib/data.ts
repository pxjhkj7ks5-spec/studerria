import { OrderStatus, ProductStatus, ReviewStatus, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { defaultTelegramUrl, publicPaymentNote } from "@/lib/constants";
import { deleteUploadFile } from "@/lib/storage";
import { formatPrice, slugify } from "@/lib/utils";
import { effectiveUnitPrice, isSaleActive, productPricePresentation } from "@/lib/pricing";
import {
  buildAnalyticsReport,
  getAnalyticsQueryStart,
  type AnalyticsRange,
} from "@/lib/analytics-report";

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

function normalizedProductImageUrl(urlPath: string) {
  return urlPath
    .trim()
    .replace(/^\/naradadruk(?=\/uploads\/)/, "")
    .replace(/[?#].*$/, "");
}

function dedupeProductImages<T extends { fileName?: string; urlPath: string }>(images: T[]) {
  const seenFiles = new Set<string>();
  const seenUrls = new Set<string>();
  return images.filter((image) => {
    const normalizedUrl = normalizedProductImageUrl(image.urlPath);
    const fileKey = image.fileName?.trim() ?? "";
    if ((fileKey && seenFiles.has(fileKey)) || (normalizedUrl && seenUrls.has(normalizedUrl))) return false;
    if (fileKey) seenFiles.add(fileKey);
    if (normalizedUrl) seenUrls.add(normalizedUrl);
    return true;
  });
}

function shuffled<T>(values: T[]) {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const target = Math.floor(Math.random() * (index + 1));
    [result[index], result[target]] = [result[target], result[index]];
  }
  return result;
}

function selectAcrossCategories<T extends { categoryId: number }>(values: T[], limit: number) {
  const groups = new Map<number, T[]>();
  for (const value of shuffled(values)) {
    groups.set(value.categoryId, [...(groups.get(value.categoryId) ?? []), value]);
  }

  const categoryGroups = shuffled([...groups.values()]).map((group) => shuffled(group));
  const selected: T[] = [];
  while (selected.length < limit && categoryGroups.some((group) => group.length > 0)) {
    for (const group of categoryGroups) {
      const next = group.shift();
      if (next) selected.push(next);
      if (selected.length === limit) break;
    }
  }
  return selected;
}

export function resolveProductPrice(product: {
  basePrice: number | null;
  priceFrom: boolean;
  saleEnabled: boolean;
  salePrice: number | null;
  salePercent: number | null;
  saleStartsAt: Date | null;
  saleEndsAt: Date | null;
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

function presentPublicProduct<T extends Prisma.ProductGetPayload<{ include: typeof publicProductInclude }>>(product: T) {
  const images = dedupeProductImages(product.images);
  const pricing = productPricePresentation(product);
  return {
    ...product,
    images,
    variants: product.variants.map((variant) => ({
      ...variant,
      regularPrice: variant.price,
      price: effectiveUnitPrice(product, variant.price, false),
    })),
    regularBasePrice: product.basePrice,
    basePrice: product.basePrice === null ? null : effectiveUnitPrice(product, product.basePrice, true),
    coverImage: resolveCoverImage({ images }),
    ...pricing,
  };
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
      paymentNote: publicPaymentNote,
      telegramUrl: defaultTelegramUrl,
      contactNote: "Надішліть приклад, розміри або ідею в Telegram, якщо потрібен індивідуальний виріб.",
    },
  });
}

export async function getVisibleCategories() {
  const [categories, counts, representativeProducts] = await Promise.all([
    prisma.category.findMany({
      where: { isVisible: true },
      orderBy: [{ sortOrder: "asc" }, { name: "asc" }],
    }),
    prisma.product.groupBy({
      by: ["categoryId"],
      where: { status: ProductStatus.published },
      _count: { _all: true },
    }),
    prisma.product.findMany({
      where: {
        status: ProductStatus.published,
        category: { isVisible: true },
        images: { some: {} },
      },
      include: {
        images: {
          orderBy: [{ isCover: "desc" }, { sortOrder: "asc" }, { id: "asc" }],
          take: 1,
        },
      },
      orderBy: [{ isFeatured: "desc" }, { sortOrder: "asc" }, { updatedAt: "desc" }],
    }),
  ]);

  const countMap = new Map(counts.map((entry) => [entry.categoryId, entry._count._all]));
  const imageMap = new Map<number, { urlPath: string; alt: string }>();

  for (const product of representativeProducts) {
    const image = product.images[0];

    if (image && !imageMap.has(product.categoryId)) {
      imageMap.set(product.categoryId, {
        urlPath: image.urlPath,
        alt: image.alt || product.title,
      });
    }
  }

  return categories.map((category) => ({
    ...category,
    publishedCount: countMap.get(category.id) ?? 0,
    representativeImage: imageMap.get(category.id) ?? null,
  }));
}

export async function getHomepageProductSections(popularLimit = 6, newLimit = 6, saleLimit = 6) {
  const products = await prisma.product.findMany({
    where: {
      status: ProductStatus.published,
      category: { isVisible: true },
    },
    include: publicProductInclude,
    orderBy: [{ createdAt: "desc" }, { updatedAt: "desc" }],
  });

  const saleProducts = selectAcrossCategories(
    products.filter((product) => isSaleActive(product)),
    saleLimit,
  );
  const saleIds = new Set(saleProducts.map((product) => product.id));
  const popularProducts = selectAcrossCategories(
    products.filter((product) => product.isFeatured && !saleIds.has(product.id)),
    popularLimit,
  );
  const popularIds = new Set(popularProducts.map((product) => product.id));
  const newProducts = products
    .filter((product) => !popularIds.has(product.id) && !saleIds.has(product.id))
    .slice(0, newLimit);
  const toPresentation = (product: (typeof products)[number]) => presentPublicProduct(product);

  return {
    saleProducts: saleProducts.map(toPresentation),
    popularProducts: popularProducts.map(toPresentation),
    newProducts: newProducts.map(toPresentation),
  };
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

  return products.map(presentPublicProduct);
}

export async function getCategoryBySlug(slug: string) {
  const category = await prisma.category.findFirst({
    where: {
      slug,
      isVisible: true,
    },
    include: {
      products: {
        where: { status: ProductStatus.published, images: { some: {} } },
        select: {
          images: {
            orderBy: [{ isCover: "desc" }, { sortOrder: "asc" }, { id: "asc" }],
            take: 1,
          },
        },
        orderBy: [{ isFeatured: "desc" }, { sortOrder: "asc" }, { updatedAt: "desc" }],
        take: 1,
      },
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
    ...presentPublicProduct(product),
    telegramUrl: getTelegramUrl((await getSiteSettings()).telegramUrl),
  };
}

export async function getShowcaseImages(limit = 6) {
  const images = await prisma.productImage.findMany({
    where: {
      product: {
        status: ProductStatus.published,
        category: { isVisible: true },
      },
    },
    include: {
      product: {
        select: {
          title: true,
          slug: true,
          category: {
            select: { name: true },
          },
        },
      },
    },
    orderBy: [{ isCover: "desc" }, { sortOrder: "asc" }, { createdAt: "desc" }],
    take: Math.max(limit * 4, limit),
  });
  return dedupeProductImages(images).slice(0, limit);
}

export async function getRelatedProducts(
  categoryId: number,
  excludeProductId: number,
  limit = 4,
) {
  const products = await prisma.product.findMany({
    where: {
      id: { not: excludeProductId },
      categoryId,
      status: ProductStatus.published,
      category: { isVisible: true },
    },
    include: publicProductInclude,
    orderBy: [{ isFeatured: "desc" }, { sortOrder: "asc" }, { updatedAt: "desc" }],
  });

  return shuffled(products).slice(0, limit).map(presentPublicProduct);
}

export async function getOrderByPublicId(publicId: string) {
  if (!/^[0-9a-f-]{36}$/i.test(publicId)) return null;

  return prisma.order.findUnique({
    where: { publicId },
    include: {
      items: { orderBy: { id: "asc" } },
    },
  });
}

async function getAdminOrderSummary(now: Date) {
  const workflowStatuses = [OrderStatus.new, OrderStatus.accepted, OrderStatus.shipped, OrderStatus.closed] as const;
  const recentStart = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const [statusGroups, allTimeValue, recentOrderCount, recentOrderValue, recentOrders] =
    await Promise.all([
      prisma.order.groupBy({
        by: ["status"],
        _count: { _all: true },
      }),
      prisma.order.aggregate({
        _sum: { total: true },
      }),
      prisma.order.count({
        where: { createdAt: { gte: recentStart } },
      }),
      prisma.order.aggregate({
        where: {
          createdAt: { gte: recentStart },
        },
        _sum: { total: true },
      }),
      prisma.order.findMany({
        select: {
          publicId: true,
          status: true,
          firstName: true,
          lastName: true,
          total: true,
          createdAt: true,
          _count: { select: { items: true } },
        },
        orderBy: { createdAt: "desc" },
        take: 5,
      }),
    ]);

  const byStatus = Object.fromEntries(
    workflowStatuses.map((status) => [status, 0]),
  ) as Record<(typeof workflowStatuses)[number], number>;
  for (const group of statusGroups) {
    if (workflowStatuses.includes(group.status as (typeof workflowStatuses)[number])) {
      byStatus[group.status as (typeof workflowStatuses)[number]] = group._count._all;
    }
  }

  return {
    totalCount: Object.values(byStatus).reduce((sum, count) => sum + count, 0),
    newCount: byStatus.new,
    activeCount: byStatus.new + byStatus.accepted + byStatus.shipped,
    acceptedCount: byStatus.accepted,
    shippedCount: byStatus.shipped,
    closedCount: byStatus.closed,
    byStatus,
    allTimeOrderValue: allTimeValue._sum.total ?? 0,
    recent: {
      days: 30,
      count: recentOrderCount,
      orderValue: recentOrderValue._sum.total ?? 0,
    },
    recentOrders,
  };
}

export async function getAdminOrders(status?: OrderStatus) {
  return prisma.order.findMany({
    where: status ? { status } : undefined,
    include: {
      _count: { select: { items: true } },
    },
    orderBy: { createdAt: "desc" },
    take: 200,
  });
}

export async function getAdminOrderByPublicId(publicId: string) {
  if (!/^[0-9a-f-]{36}$/i.test(publicId)) return null;
  return prisma.order.findUnique({
    where: { publicId },
    include: {
      items: { orderBy: { id: "asc" } },
      events: { orderBy: { createdAt: "asc" } },
      promoCode: { select: { id: true, code: true } },
    },
  });
}

export async function updateOrderStatus(publicId: string, status: OrderStatus, actor = "admin") {
  return prisma.$transaction(async (transaction) => {
    const order = await transaction.order.findUnique({ where: { publicId }, select: { id: true, status: true } });
    if (!order) throw new Error("Замовлення не знайдено.");
    if (order.status === status) return order;
    await transaction.order.update({ where: { id: order.id }, data: { status } });
    await transaction.orderEvent.create({ data: { orderId: order.id, eventType: "status", fromStatus: order.status, toStatus: status, actor } });
    return { ...order, status };
  });
}

export async function addOrderComment(publicId: string, comment: string, actor = "admin") {
  const order = await prisma.order.findUnique({ where: { publicId }, select: { id: true, status: true } });
  if (!order) throw new Error("Замовлення не знайдено.");
  return prisma.orderEvent.create({ data: { orderId: order.id, eventType: "comment", toStatus: order.status, comment, actor } });
}

export async function permanentlyDeleteOrder(publicId: string) {
  return prisma.$transaction(async (transaction) => {
    const order = await transaction.order.findUnique({
      where: { publicId },
      select: { id: true, promoCodeId: true },
    });
    if (!order) return "missing" as const;

    await transaction.order.delete({ where: { id: order.id } });
    if (order.promoCodeId) {
      await transaction.promoCode.updateMany({
        where: { id: order.promoCodeId, useCount: { gt: 0 } },
        data: { useCount: { decrement: 1 } },
      });
    }
    return "deleted" as const;
  });
}

export async function getApprovedReviews(limit = 60) {
  return prisma.review.findMany({
    where: { status: ReviewStatus.approved },
    include: { images: { orderBy: [{ sortOrder: "asc" }, { id: "asc" }] } },
    orderBy: [{ createdAt: "desc" }],
    take: limit,
  });
}

export async function getAdminReviews(status?: ReviewStatus) {
  return prisma.review.findMany({
    where: status ? { status } : undefined,
    include: { images: { orderBy: [{ sortOrder: "asc" }, { id: "asc" }] } },
    orderBy: [{ createdAt: "desc" }],
    take: 200,
  });
}

export async function getAdminReview(id: number) {
  return prisma.review.findUnique({
    where: { id },
    include: { images: { orderBy: [{ sortOrder: "asc" }, { id: "asc" }] } },
  });
}

export async function setReviewStatus(id: number, status: ReviewStatus) {
  return prisma.review.update({
    where: { id },
    data: { status, moderatedAt: new Date() },
  });
}

export async function deleteReview(id: number) {
  const review = await getAdminReview(id);
  if (!review) return;
  await prisma.review.delete({ where: { id } });
  await Promise.all(review.images.map((image) => deleteUploadFile(image.fileName)));
}

export async function getAdminPromoCodes() {
  return prisma.promoCode.findMany({
    include: { orders: { select: { publicId: true, total: true, createdAt: true, source: true }, orderBy: { createdAt: "desc" }, take: 8 } },
    orderBy: { createdAt: "desc" },
  });
}

export async function getAdminPromoCode(id: number) {
  return prisma.promoCode.findUnique({
    where: { id },
    include: { orders: { select: { publicId: true, total: true, discountAmount: true, createdAt: true, source: true }, orderBy: { createdAt: "desc" }, take: 100 } },
  });
}

export async function savePromoCode(input: {
  id?: number;
  code: string;
  type: "percentage" | "fixed";
  value: number;
  usageLimit: number | null;
  expiresAt: Date | null;
  enabled: boolean;
}) {
  const { id, ...values } = input;
  const data = { ...values, code: input.code.trim().normalize("NFKC").toLocaleUpperCase("uk-UA") };
  if (id) return prisma.promoCode.update({ where: { id }, data });
  return prisma.promoCode.create({ data });
}

export async function deleteUnusedPromoCode(id: number) {
  const deleted = await prisma.promoCode.deleteMany({
    where: {
      id,
      useCount: 0,
      orders: { none: {} },
    },
  });
  if (deleted.count === 1) return "deleted" as const;

  const exists = await prisma.promoCode.findUnique({
    where: { id },
    select: { id: true },
  });
  return exists ? "used" as const : "missing" as const;
}

export async function createAnalyticsIpExclusion(input: {
  addressHash: string;
  addressHint: string;
  label: string;
}) {
  return prisma.analyticsIpExclusion.create({ data: input });
}

export async function deleteAnalyticsIpExclusion(id: number) {
  return prisma.analyticsIpExclusion.deleteMany({ where: { id } });
}

export async function getAdminDashboardData(input?: {
  analyticsRange?: AnalyticsRange;
}) {
  const telegramChannel = (process.env.TELEGRAM_CHANNEL_USERNAME || "naradaprint")
    .trim()
    .replace(/^@/, "");
  const analyticsRange = input?.analyticsRange ?? 30;
  const analyticsNow = new Date();
  const [settings, categories, products, telegramSync, recentTelegramImports, analyticsEvents, analyticsIpExclusions, orders] = await Promise.all([
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
    prisma.telegramChannelSync.findUnique({
      where: { channel: telegramChannel },
    }),
    prisma.telegramPostImport.findMany({
      where: { channel: telegramChannel },
      include: {
        product: {
          select: {
            id: true,
            slug: true,
            status: true,
          },
        },
      },
      orderBy: [{ updatedAt: "desc" }],
      take: 8,
    }),
    prisma.analyticsEvent.findMany({
      where: {
        createdAt: {
          gte: getAnalyticsQueryStart(analyticsRange, analyticsNow),
        },
      },
      orderBy: [{ createdAt: "desc" }],
      take: 100_000,
    }),
    prisma.analyticsIpExclusion.findMany({
      orderBy: [{ createdAt: "desc" }],
      take: 100,
    }),
    getAdminOrderSummary(analyticsNow),
  ]);

  return {
    settings,
    categories,
    products: products.map((product) => ({
      ...product,
      coverImage: resolveCoverImage(product),
      priceLabel: resolveProductPrice(product),
    })),
    telegramAutomation: {
      channel: telegramChannel,
      enabled: !/^(0|false|no|off)$/i.test(
        process.env.TELEGRAM_AUTO_IMPORT_ENABLED || "true",
      ),
      sync: telegramSync,
      recentImports: recentTelegramImports,
    },
    analytics: buildAnalyticsReport(
      analyticsEvents,
      analyticsRange,
      analyticsNow,
    ),
    analyticsIpExclusions,
    orders,
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
  saleEnabled: boolean;
  salePrice: number | null;
  salePercent: number | null;
  saleStartsAt: Date | null;
  saleEndsAt: Date | null;
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
      saleEnabled: input.saleEnabled,
      salePrice: input.salePrice,
      salePercent: input.salePercent,
      saleStartsAt: input.saleStartsAt,
      saleEndsAt: input.saleEndsAt,
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
