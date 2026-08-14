import type { Prisma } from "@prisma/client";

type Transaction = Prisma.TransactionClient;

export type StockWarning = {
  productId: number;
  variantId: number | null;
  productTitle: string;
  variantLabel: string;
  balanceAfter: number;
};

async function applyDelta(
  transaction: Transaction,
  input: { productId: number; variantId: number | null; delta: number },
) {
  if (input.variantId) {
    const variant = await transaction.productVariant.update({
      where: { id: input.variantId },
      data: { stockQuantity: { increment: input.delta } },
      select: { stockQuantity: true, productId: true },
    });
    if (variant.productId !== input.productId) throw new Error("Варіант не належить товару.");
    return variant.stockQuantity;
  }
  const product = await transaction.product.update({
    where: { id: input.productId },
    data: { stockQuantity: { increment: input.delta } },
    select: { stockQuantity: true },
  });
  return product.stockQuantity;
}

export async function reserveOrderInventory(transaction: Transaction, orderId: number) {
  const items = await transaction.orderItem.findMany({
    where: { orderId, productId: { not: null } },
    select: {
      id: true,
      productId: true,
      variantId: true,
      quantity: true,
      productTitle: true,
      variantLabel: true,
    },
  });
  const warnings: StockWarning[] = [];
  for (const item of items) {
    if (!item.productId) continue;
    const idempotencyKey = `order:${orderId}:item:${item.id}:reserve`;
    const exists = await transaction.stockMovement.findUnique({ where: { idempotencyKey } });
    if (exists) continue;
    const delta = -item.quantity;
    const balanceAfter = await applyDelta(transaction, { productId: item.productId, variantId: item.variantId, delta });
    await transaction.stockMovement.create({
      data: {
        idempotencyKey,
        productId: item.productId,
        variantId: item.variantId,
        orderId,
        orderItemId: item.id,
        delta,
        balanceAfter,
        reason: "order_reserved",
      },
    });
    if (balanceAfter < 0) warnings.push({
      productId: item.productId,
      variantId: item.variantId,
      productTitle: item.productTitle,
      variantLabel: item.variantLabel,
      balanceAfter,
    });
  }
  return warnings;
}

export async function restoreOrderInventory(transaction: Transaction, orderId: number) {
  const reservations = await transaction.stockMovement.findMany({
    where: { orderId, reason: "order_reserved" },
    orderBy: { id: "asc" },
  });
  for (const reservation of reservations) {
    const idempotencyKey = `${reservation.idempotencyKey}:cancel`;
    const exists = await transaction.stockMovement.findUnique({ where: { idempotencyKey } });
    if (exists) continue;
    const delta = -reservation.delta;
    const balanceAfter = await applyDelta(transaction, {
      productId: reservation.productId,
      variantId: reservation.variantId,
      delta,
    });
    await transaction.stockMovement.create({
      data: {
        idempotencyKey,
        productId: reservation.productId,
        variantId: reservation.variantId,
        orderId,
        orderItemId: reservation.orderItemId,
        delta,
        balanceAfter,
        reason: "order_cancelled",
      },
    });
  }
}

export async function setInventoryQuantity(transaction: Transaction, input: {
  productId: number;
  variantId: number | null;
  quantity: number;
  staffUserId: number;
  note: string;
}) {
  const current = input.variantId
    ? (await transaction.productVariant.findUniqueOrThrow({ where: { id: input.variantId }, select: { productId: true, stockQuantity: true } }))
    : (await transaction.product.findUniqueOrThrow({ where: { id: input.productId }, select: { stockQuantity: true } }));
  if ("productId" in current && current.productId !== input.productId) throw new Error("Варіант не належить товару.");
  const delta = input.quantity - current.stockQuantity;
  if (delta === 0) return current.stockQuantity;
  const balanceAfter = await applyDelta(transaction, { productId: input.productId, variantId: input.variantId, delta });
  await transaction.stockMovement.create({
    data: {
      idempotencyKey: `adjust:${input.staffUserId}:${Date.now()}:${input.productId}:${input.variantId ?? "base"}`,
      productId: input.productId,
      variantId: input.variantId,
      staffUserId: input.staffUserId,
      delta,
      balanceAfter,
      reason: "manual_adjustment",
      note: input.note,
    },
  });
  return balanceAfter;
}
