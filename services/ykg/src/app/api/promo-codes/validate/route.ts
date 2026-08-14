import { NextResponse } from "next/server";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { OrderPricingError, priceRequestedItems, validatePromoCode } from "@/lib/order-pricing";

const schema = z.object({
  code: z.string().max(32),
  items: z.array(z.object({ productId: z.number().int().positive(), variantId: z.number().int().positive().nullable(), quantity: z.number().int().min(1).max(20) })).min(1).max(50),
});

export async function POST(request: Request) {
  const parsed = schema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "Перевірте промокод і кошик." }, { status: 400 });
  try {
    const pricing = await priceRequestedItems(prisma, parsed.data.items);
    const result = await validatePromoCode(prisma, parsed.data.code, pricing.promoBase);
    if (!result) return NextResponse.json({ error: "Введіть промокод." }, { status: 400 });
    return NextResponse.json({
      code: result.promo.code,
      subtotal: pricing.subtotal,
      saleDiscountAmount: pricing.saleDiscountAmount,
      discountAmount: result.discountAmount,
      total: result.total,
      label: result.promo.type === "percentage" ? `${result.promo.value}%` : `${result.promo.value} грн`,
    });
  } catch (error) {
    return NextResponse.json({ error: error instanceof OrderPricingError ? error.message : "Не вдалося перевірити промокод." }, { status: 400 });
  }
}
