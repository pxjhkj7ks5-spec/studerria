import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  await prisma.$executeRawUnsafe(`
    INSERT INTO "OrderEvent" ("orderId", "eventType", "fromStatus", "toStatus", comment, actor, "createdAt")
    SELECT id, 'created', '', status, '', 'system', "createdAt"
    FROM "Order"
    WHERE NOT EXISTS (SELECT 1 FROM "OrderEvent" WHERE "OrderEvent"."orderId" = "Order".id)
  `);
  await prisma.$executeRawUnsafe(`
    INSERT INTO "OrderEvent" ("orderId", "eventType", "fromStatus", "toStatus", comment, actor, "createdAt")
    SELECT id, 'status_migration', status,
      CASE WHEN status IN ('confirmed', 'processing') THEN 'accepted' ELSE 'closed' END,
      'Автоматично перенесено до нової системи статусів.', 'system', CURRENT_TIMESTAMP
    FROM "Order"
    WHERE status IN ('confirmed', 'processing', 'completed', 'cancelled')
      AND NOT EXISTS (SELECT 1 FROM "OrderEvent" WHERE "OrderEvent"."orderId" = "Order".id AND "eventType" = 'status_migration')
  `);
  await prisma.$executeRawUnsafe(`UPDATE "Order" SET status = 'accepted' WHERE status IN ('confirmed', 'processing')`);
  await prisma.$executeRawUnsafe(`UPDATE "Order" SET status = 'closed' WHERE status IN ('completed', 'cancelled')`);
  await prisma.$executeRawUnsafe(`UPDATE "Order" SET subtotal = total WHERE subtotal = 0 AND "discountAmount" = 0`);
  await prisma.$executeRawUnsafe(`UPDATE "OrderItem" SET "regularUnitPrice" = "unitPrice" WHERE "regularUnitPrice" = 0`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
