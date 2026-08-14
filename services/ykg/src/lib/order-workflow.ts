import type { OrderStatus, Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { restoreOrderInventory } from "@/lib/inventory";

type Actor = { label: string; staffUserId?: number | null };

const transitions: Record<OrderStatus, readonly OrderStatus[]> = {
  new: ["accepted", "cancelled"],
  accepted: ["shipped", "cancelled"],
  shipped: ["completed"],
  completed: [],
  cancelled: [],
};

export function canTransitionOrder(from: OrderStatus, to: OrderStatus) {
  return from === to || transitions[from].includes(to);
}

export async function transitionOrderStatus(
  publicId: string,
  status: OrderStatus,
  actor: Actor,
  transaction?: Prisma.TransactionClient,
) {
  const run = async (db: Prisma.TransactionClient) => {
    const order = await db.order.findUnique({ where: { publicId }, select: { id: true, status: true } });
    if (!order) throw new Error("Замовлення не знайдено.");
    if (order.status === status) return { ...order, changed: false };
    if (!canTransitionOrder(order.status, status)) throw new Error("Недозволений перехід статусу.");
    if (status === "cancelled") await restoreOrderInventory(db, order.id);
    await db.order.update({ where: { id: order.id }, data: { status } });
    await db.orderEvent.create({
      data: {
        orderId: order.id,
        eventType: "status",
        fromStatus: order.status,
        toStatus: status,
        actor: actor.label,
        staffUserId: actor.staffUserId ?? null,
        isPublic: true,
      },
    });
    await db.auditEvent.create({
      data: {
        staffUserId: actor.staffUserId ?? null,
        actorLabel: actor.label,
        action: "order.status_changed",
        entityType: "order",
        entityId: publicId,
        detailsJson: JSON.stringify({ from: order.status, to: status }),
      },
    });
    return { ...order, status, changed: true };
  };
  return transaction ? run(transaction) : prisma.$transaction(run);
}

export async function addInternalOrderComment(publicId: string, comment: string, actor: Actor) {
  return prisma.$transaction(async (db) => {
    const order = await db.order.findUnique({ where: { publicId }, select: { id: true, status: true } });
    if (!order) throw new Error("Замовлення не знайдено.");
    const event = await db.orderEvent.create({
      data: {
        orderId: order.id,
        eventType: "comment",
        toStatus: order.status,
        comment,
        actor: actor.label,
        staffUserId: actor.staffUserId ?? null,
        isPublic: false,
      },
    });
    await db.auditEvent.create({
      data: {
        staffUserId: actor.staffUserId ?? null,
        actorLabel: actor.label,
        action: "order.comment_added",
        entityType: "order",
        entityId: publicId,
      },
    });
    return event;
  });
}
