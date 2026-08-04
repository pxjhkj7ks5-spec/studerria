import assert from "node:assert/strict";
import test from "node:test";
import {
  applyManualOrderText,
  buildManualOrderCreateData,
  chooseManualOrderKind,
  createManualOrderSession,
  selectManualCatalogItem,
} from "../src/lib/manual-order";

function apply(session: ReturnType<typeof createManualOrderSession>, value: string) {
  const result = applyManualOrderText(session, value);
  assert.equal(result.ok, true);
  if (!result.ok) throw new Error(result.error);
  return result.session;
}

function enteredCustomer() {
  let session = createManualOrderSession();
  session = apply(session, "Олена Петренко");
  session = apply(session, "+380 67 123 45 67");
  session = apply(session, "@olena_print");
  session = apply(session, "Київ, відділення №15");
  return session;
}

test("manual order collects customer fields in separate sequential steps", () => {
  const session = enteredCustomer();

  assert.equal(session.step, "kind");
  assert.equal(session.customerName, "Олена Петренко");
  assert.equal(session.phone, "+380 67 123 45 67");
  assert.equal(session.telegramContact, "@olena_print");
  assert.equal(session.deliveryText, "Київ, відділення №15");
});

test("manual catalog order keeps the selected product relation and current price", () => {
  let session = chooseManualOrderKind(enteredCustomer(), "catalog");
  session = selectManualCatalogItem(session, {
    productId: 78,
    productSlug: "raizer-pid-kolimator",
    productTitle: "Райзер під коліматор",
    productUrl: "https://example.com/naradadruk/product/raizer-pid-kolimator",
    variantId: null,
    variantLabel: "",
    unitPrice: 225,
    regularUnitPrice: 250,
  });

  const data = buildManualOrderCreateData(session, "11111111-1111-4111-8111-111111111111");

  assert.equal(data.source, "manual");
  assert.equal(data.deliveryMethod, "branch");
  assert.equal(data.deliveryDestination, "Київ, відділення №15");
  assert.equal(data.cityName, "");
  assert.equal(data.cityRef, "");
  assert.equal(data.destinationRef, "");
  assert.equal(data.courierAddress, "");
  assert.equal(data.phone, "+380 67 123 45 67");
  assert.equal(data.telegramContact, "@olena_print");
  assert.equal(data.items.create.productId, 78);
  assert.equal(data.items.create.unitPrice, 225);
  assert.equal(data.saleDiscountAmount, 25);
  assert.equal(data.total, 225);
});

test("manual unique order stores its description and agreed price", () => {
  let session = chooseManualOrderKind(enteredCustomer(), "unique");
  session = apply(session, "Індивідуальне кріплення за ескізом клієнта");
  session = apply(session, "740 грн");

  const data = buildManualOrderCreateData(session, "22222222-2222-4222-8222-222222222222");

  assert.equal(data.items.create.productTitle, "Індивідуальне кріплення за ескізом клієнта");
  assert.equal(data.items.create.productUrl, "");
  assert.equal(data.items.create.unitPrice, 740);
  assert.equal(data.total, 740);
});

test("manual order rejects invalid phone, Telegram contact, and zero price", () => {
  const named = apply(createManualOrderSession(), "Олена");
  assert.equal(applyManualOrderText(named, "123").ok, false);

  const phone = apply(named, "+380671234567");
  assert.equal(applyManualOrderText(phone, "посилання з пробілами!").ok, false);

  let unique = chooseManualOrderKind(enteredCustomer(), "unique");
  unique = apply(unique, "Унікальний виріб");
  assert.equal(applyManualOrderText(unique, "0").ok, false);
});
