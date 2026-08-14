import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { closeSync, mkdtempSync, openSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const directory = mkdtempSync(join(tmpdir(), "ykg-commerce-test-"));
const databasePath = join(directory, "test.db");
closeSync(openSync(databasePath, "w"));
process.env.DATABASE_URL = `file:${databasePath}`;
Object.assign(process.env, { NODE_ENV: "test" });
process.env.YKG_PUBLIC_URL = "https://example.test/ykg";
process.env.NEXT_PUBLIC_BASE_PATH = "/ykg";
execFileSync(join(process.cwd(), "node_modules/.bin/prisma"), ["db", "push", "--skip-generate"], { cwd: process.cwd(), env: process.env, stdio: "ignore" });

let prisma: (typeof import("../src/lib/prisma"))["prisma"];
let reserveOrderInventory: (typeof import("../src/lib/inventory"))["reserveOrderInventory"];
let transitionOrderStatus: (typeof import("../src/lib/order-workflow"))["transitionOrderStatus"];
let getCatalogProducts: (typeof import("../src/lib/data"))["getCatalogProducts"];
let getOrderByPublicId: (typeof import("../src/lib/data"))["getOrderByPublicId"];
let authorizeTelegramActor: (typeof import("../src/lib/telegram-access"))["authorizeTelegramActor"];
let hashPassword: (typeof import("../src/lib/auth"))["hashPassword"];
let verifyPassword: (typeof import("../src/lib/auth"))["verifyPassword"];

test.before(async () => {
  ({ prisma } = await import("../src/lib/prisma"));
  ({ reserveOrderInventory } = await import("../src/lib/inventory"));
  ({ transitionOrderStatus } = await import("../src/lib/order-workflow"));
  ({ getCatalogProducts, getOrderByPublicId } = await import("../src/lib/data"));
  ({ authorizeTelegramActor } = await import("../src/lib/telegram-access"));
  ({ hashPassword, verifyPassword } = await import("../src/lib/auth"));
});

async function createOrder(publicId: string, productId: number, productSlug: string) {
  return prisma.order.create({ data: {
    publicId, firstName: "Олена", lastName: "К.", phone: "+380671234567", telegramContact: "@customer",
    cityName: "Київ", deliveryMethod: "branch", deliveryDestination: "Відділення 1", paymentMethod: "transfer", total: 900, subtotal: 900,
    events: { create: [{ eventType: "created", toStatus: "new", actor: "test", isPublic: true }, { eventType: "comment", toStatus: "new", actor: "test", comment: "secret", isPublic: false }] },
    items: { create: { productId, productSlug, productTitle: "YKG Test", productUrl: `https://example.test/ykg/product/${productSlug}`, quantity: 1, unitPrice: 900, regularUnitPrice: 900, totalPrice: 900 } },
  } });
}

test("commerce stock, status, privacy, auth and Telegram allowlist", async (context) => {
  context.after(async () => prisma.$disconnect());
  const category = await prisma.category.create({ data: { name: "Патчі", slug: "patches", isVisible: true } });
  const product = await prisma.product.create({ data: { title: "YKG Test", slug: "ykg-test", categoryId: category.id, status: "published", basePrice: 900, stockQuantity: 1 } });
  const first = await createOrder("11111111-1111-4111-8111-111111111111", product.id, product.slug);
  const second = await createOrder("22222222-2222-4222-8222-222222222222", product.id, product.slug);

  await Promise.all([
    prisma.$transaction((db) => reserveOrderInventory(db, first.id)),
    prisma.$transaction((db) => reserveOrderInventory(db, second.id)),
  ]);
  assert.equal((await prisma.product.findUniqueOrThrow({ where: { id: product.id } })).stockQuantity, -1);
  assert.equal(await prisma.stockMovement.count({ where: { reason: "order_reserved" } }), 2);

  await transitionOrderStatus(first.publicId, "cancelled", { label: "test" });
  await transitionOrderStatus(first.publicId, "cancelled", { label: "test" });
  assert.equal((await prisma.product.findUniqueOrThrow({ where: { id: product.id } })).stockQuantity, 0);
  assert.equal(await prisma.stockMovement.count({ where: { orderId: first.id, reason: "order_cancelled" } }), 1);
  await transitionOrderStatus(second.publicId, "accepted", { label: "test" });
  await transitionOrderStatus(second.publicId, "shipped", { label: "test" });
  await assert.rejects(() => transitionOrderStatus(second.publicId, "cancelled", { label: "test" }), /Недозволений/);

  const publicProducts = await getCatalogProducts({});
  assert.equal(publicProducts[0]?.availability, "made_to_order");
  assert.equal("stockQuantity" in (publicProducts[0] || {}), false);
  assert.equal("stockQuantity" in (publicProducts[0]?.variants[0] || {}), false);
  const publicOrder = await getOrderByPublicId(first.publicId);
  assert.ok(publicOrder);
  assert.equal(publicOrder.events.some((event) => event.eventType === "comment"), false);

  const encoded = hashPassword("long-enough-password");
  assert.equal(verifyPassword("long-enough-password", encoded), true);
  assert.equal(verifyPassword("wrong", encoded), false);
  await prisma.staffUser.create({ data: { username: "owner", displayName: "Owner", passwordHash: encoded, role: "owner", telegramUserId: "100", isActive: true } });
  await prisma.staffUser.create({ data: { username: "blocked", displayName: "Blocked", passwordHash: encoded, role: "manager", telegramUserId: "200", isActive: false } });
  assert.equal((await authorizeTelegramActor(prisma, 100))?.role, "owner");
  assert.equal(await authorizeTelegramActor(prisma, 200), null);
  assert.equal(await authorizeTelegramActor(prisma, 999), null);
});
