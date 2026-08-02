import assert from "node:assert/strict";
import test from "node:test";
import {
  parseTelegramProductTemplate,
  telegramProductTemplate,
} from "../src/lib/telegram-product-template";

test("parses the documented template as a published product", () => {
  const result = parseTelegramProductTemplate(telegramProductTemplate);

  assert.equal(result.matched, true);
  if (!result.matched) {
    return;
  }

  assert.equal(result.ok, true);

  if (!result.ok) {
    return;
  }

  assert.equal(result.product.title, "Настінне кріплення для навушників");
  assert.equal(result.product.category, "Інше");
  assert.equal(result.product.basePrice, 350);
  assert.equal(result.product.shouldPublish, true);
  assert.equal(result.product.material, "PETG");
});

test("keeps a valid product as a draft when publication is not affirmative", () => {
  const result = parseTelegramProductTemplate(`#товар
Назва: Підставка для телефона
Категорія: 3D друк
Ціна: від 240 грн
Опис: Компактна підставка для робочого столу.
Публікація: ні`);

  assert.equal(result.matched, true);
  if (!result.matched) {
    return;
  }

  assert.equal(result.ok, true);

  if (!result.ok) {
    return;
  }

  assert.equal(result.product.basePrice, 240);
  assert.equal(result.product.priceFrom, true);
  assert.equal(result.product.shouldPublish, false);
});

test("parses multiline descriptions and variants", () => {
  const result = parseTelegramProductTemplate(`#товар
Назва: Настільний органайзер
Категорія: Декор
Опис:
Органайзер для канцелярії.
Можна замовити у двох кольорах.
Варіанти:
- Чорний — 350 грн
- Білий — від 370 грн
Публікація: так`);

  assert.equal(result.matched, true);
  if (!result.matched) {
    return;
  }

  assert.equal(result.ok, true);

  if (!result.ok) {
    return;
  }

  assert.equal(
    result.product.description,
    "Органайзер для канцелярії.\nМожна замовити у двох кольорах.",
  );
  assert.deepEqual(result.product.variants, [
    { label: "Чорний", price: 350, priceFrom: false },
    { label: "Білий", price: 370, priceFrom: true },
  ]);
});

test("reports missing required template fields", () => {
  const result = parseTelegramProductTemplate(`#товар
Назва: X
Опис: коротко`);

  assert.equal(result.matched, true);
  if (!result.matched) {
    return;
  }

  assert.equal(result.ok, false);

  if (result.matched && !result.ok) {
    assert.match(result.errors.join(" "), /Назва/);
    assert.match(result.errors.join(" "), /Категорія/);
    assert.match(result.errors.join(" "), /Ціна/);
  }
});

test("ignores ordinary channel posts", () => {
  assert.deepEqual(
    parseTelegramProductTemplate("Сьогодні показуємо процес друку нового виробу."),
    { matched: false },
  );
});
