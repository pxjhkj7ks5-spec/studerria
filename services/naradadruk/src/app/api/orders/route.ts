import { randomUUID } from "node:crypto";
import { ProductStatus } from "@prisma/client";
import { NextResponse } from "next/server";
import { withBasePath } from "@/lib/base-path";
import { siteBaseUrl } from "@/lib/constants";
import { getOrderValidationMessage, orderInputSchema } from "@/lib/order-validation";
import { prisma } from "@/lib/prisma";
import { notifyOwnerAboutOrder } from "@/lib/telegram-orders";

class CheckoutError extends Error {}

export async function POST(request: Request) {
  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    return NextResponse.json({ error: "Некоректний формат запиту." }, { status: 400 });
  }

  const parsed = orderInputSchema.safeParse(payload);
  if (!parsed.success) {
    return NextResponse.json(
      { error: getOrderValidationMessage(parsed.error) },
      { status: 400 },
    );
  }

  const aggregated = new Map<string, { productId: number; variantId: number | null; quantity: number }>();
  for (const item of parsed.data.items) {
    const key = `${item.productId}:${item.variantId ?? "base"}`;
    const existing = aggregated.get(key);
    const quantity = (existing?.quantity ?? 0) + item.quantity;
    if (quantity > 20) {
      return NextResponse.json({ error: "Максимальна кількість однієї позиції — 20." }, { status: 400 });
    }
    aggregated.set(key, { ...item, quantity });
  }

  const requestedItems = [...aggregated.values()];
  const products = await prisma.product.findMany({
    where: {
      id: { in: [...new Set(requestedItems.map((item) => item.productId))] },
      status: ProductStatus.published,
      category: { isVisible: true },
    },
    include: { variants: true },
  });
  const productMap = new Map(products.map((product) => [product.id, product]));

  try {
    const orderItems = requestedItems.map((requested) => {
      const product = productMap.get(requested.productId);
      if (!product) throw new CheckoutError("Один із товарів уже недоступний. Оновіть кошик.");

      const variant = requested.variantId
        ? product.variants.find((entry) => entry.id === requested.variantId)
        : null;
      if (requested.variantId && !variant) throw new CheckoutError(`Варіант «${product.title}» уже недоступний.`);
      if (product.variants.length > 0 && !variant) throw new CheckoutError(`Оберіть варіант товару «${product.title}».`);

      const unitPrice = variant?.price ?? product.basePrice;
      if (typeof unitPrice !== "number" || unitPrice < 0) {
        throw new CheckoutError(`Для товару «${product.title}» потрібно уточнити ціну в Telegram.`);
      }
      const productUrl = new URL(withBasePath(`/product/${product.slug}`), siteBaseUrl).toString();
      return {
        productId: product.id,
        productSlug: product.slug,
        productTitle: product.title,
        productUrl,
        variantId: variant?.id ?? null,
        variantLabel: variant?.label ?? "",
        quantity: requested.quantity,
        unitPrice,
        totalPrice: unitPrice * requested.quantity,
      };
    });
    const total = orderItems.reduce((sum, item) => sum + item.totalPrice, 0);
    const publicId = randomUUID();

    const order = await prisma.order.create({
      data: {
        publicId,
        firstName: parsed.data.firstName,
        lastName: parsed.data.lastName,
        comment: parsed.data.comment,
        phone: parsed.data.phone,
        telegramContact: parsed.data.telegramContact,
        cityName: parsed.data.cityName,
        cityRef: parsed.data.cityRef,
        deliveryMethod: parsed.data.deliveryMethod,
        deliveryDestination: parsed.data.deliveryDestination,
        destinationRef: parsed.data.destinationRef,
        courierAddress: parsed.data.courierAddress,
        paymentMethod: parsed.data.paymentMethod,
        total,
        items: { create: orderItems },
      },
      include: { items: true },
    });

    try {
      const notification = await notifyOwnerAboutOrder(order);
      await prisma.order.update({
        where: { id: order.id },
        data: {
          notificationStatus: notification.status,
          notificationError: notification.error,
        },
      });
    } catch (notificationError) {
      console.error("[orders] notification status update failed", notificationError);
    }

    return NextResponse.json({ publicId, total }, { status: 201 });
  } catch (error) {
    if (error instanceof CheckoutError) {
      return NextResponse.json({ error: error.message }, { status: 400 });
    }
    console.error("[orders] creation failed", error);
    return NextResponse.json({ error: "Не вдалося оформити замовлення. Спробуйте ще раз." }, { status: 500 });
  }
}
