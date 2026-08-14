import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { getOrderValidationMessage, orderInputSchema } from "@/lib/order-validation";
import { OrderPricingError, priceRequestedItems, validatePromoCode } from "@/lib/order-pricing";
import { prisma } from "@/lib/prisma";
import { notifyOwnerAboutOrder } from "@/lib/telegram-orders";
import { reserveOrderInventory } from "@/lib/inventory";

export async function POST(request: Request) {
  const parsed = orderInputSchema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: getOrderValidationMessage(parsed.error) }, { status: 400 });

  try {
    const result = await prisma.$transaction(async (transaction) => {
      const pricing = await priceRequestedItems(transaction, parsed.data.items);
      const promoResult = await validatePromoCode(transaction, parsed.data.promoCode, pricing.promoBase);
      if (promoResult) {
        const redeemed = await transaction.promoCode.updateMany({
          where: {
            id: promoResult.promo.id,
            enabled: true,
            useCount: {
              equals: promoResult.promo.useCount,
              ...(promoResult.promo.usageLimit !== null ? { lt: promoResult.promo.usageLimit } : {}),
            },
            OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
          },
          data: { useCount: { increment: 1 } },
        });
        if (redeemed.count !== 1) throw new OrderPricingError("Промокод щойно став недоступним. Перевірте його ще раз.");
      }
      const total = promoResult?.total ?? pricing.promoBase;
      const order = await transaction.order.create({
        data: {
          publicId: randomUUID(),
          source: "website",
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
          subtotal: pricing.subtotal,
          saleDiscountAmount: pricing.saleDiscountAmount,
          discountAmount: promoResult?.discountAmount ?? 0,
          promoCodeId: promoResult?.promo.id ?? null,
          promoCodeSnapshot: promoResult?.promo.code ?? "",
          promoTypeSnapshot: promoResult?.promo.type ?? null,
          promoValueSnapshot: promoResult?.promo.value ?? null,
          total,
          items: { create: pricing.items },
          events: { create: { eventType: "created", toStatus: "new", actor: "website", isPublic: true } },
        },
        include: { items: true, events: true },
      });
      const stockWarnings = await reserveOrderInventory(transaction, order.id);
      return { order, stockWarnings };
    });

    const notification = await notifyOwnerAboutOrder(result.order, result.stockWarnings);
    await prisma.order.update({ where: { id: result.order.id }, data: { notificationStatus: notification.status, notificationError: notification.error, telegramMessageId: notification.messageId } })
      .catch((error) => console.error("[orders] notification status update failed", error));
    return NextResponse.json({ publicId: result.order.publicId, total: result.order.total }, { status: 201 });
  } catch (error) {
    if (error instanceof OrderPricingError) return NextResponse.json({ error: error.message }, { status: 400 });
    console.error("[orders] creation failed", error);
    return NextResponse.json({ error: "Не вдалося оформити замовлення. Спробуйте ще раз." }, { status: 500 });
  }
}
