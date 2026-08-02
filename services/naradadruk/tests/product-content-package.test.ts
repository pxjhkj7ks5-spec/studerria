import assert from "node:assert/strict";
import test from "node:test";
import {
  buildTelegramProductPost,
  calculatePrivatePriceGuidance,
  parseProductContentPackage,
} from "../src/lib/product-content-package";

const fullPackage = `НАЗВА: Настінний органайзер
КАТЕГОРІЯ: Інше
КОРОТКИЙ ОПИС: Практичний органайзер для дрібних речей.
ОПИС ДЛЯ САЙТУ: Допомагає тримати потрібні дрібниці поруч і звільняє робочу поверхню.
ДЛЯ КОГО: Для домашнього робочого місця та майстерні.
ПЕРЕВАГИ:
- швидкий доступ
- компактне розміщення
ХАРАКТЕРИСТИКИ:
- настінне кріплення
СУМІСНІСТЬ: Потребує рівної поверхні.
КОМПЛЕКТАЦІЯ: Один органайзер.
ТЕКСТ TELEGRAM: Звільняє робочу поверхню й тримає дрібні речі на своєму місці.
МАТЕРІАЛ: PETG
ТЕРМІН: 1–3 дні
ВАГА, Г: 125 г
ЦІНА ПРОДАЖУ: 550 грн
ДЖЕРЕЛО: https://makerworld.com/en/models/123
АВТОР МОДЕЛІ: Maker Author
ЛІЦЕНЗІЯ: Standard Digital File License`;

test("parses the complete multiline product content package", () => {
  const result = parseProductContentPackage(fullPackage);
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.product.title, "Настінний органайзер");
  assert.equal(result.product.benefitsNote, "- швидкий доступ\n- компактне розміщення");
  assert.equal(result.product.printWeightGrams, 125);
  assert.equal(result.product.price, 550);
  assert.equal(result.product.sourceModelAuthor, "Maker Author");
});

test("accepts optional fields marked as unknown and reports unknown package headings", () => {
  const result = parseProductContentPackage(fullPackage
    .replace("125 г", "невідомо")
    .replace("550 грн", "невідомо")
    .replace("ЛІЦЕНЗІЯ:", "ДОДАТКОВЕ ПОЛЕ: не використовується\nЛІЦЕНЗІЯ:"));
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.product.printWeightGrams, null);
  assert.equal(result.product.price, null);
  assert.deepEqual(result.warnings, ["Невідоме поле «ДОДАТКОВЕ ПОЛЕ» пропущено."]);
});

test("rejects missing required copy and malformed private values", () => {
  const result = parseProductContentPackage(`НАЗВА: X\nВАГА, Г: багато\nЦІНА ПРОДАЖУ: abc\nДЖЕРЕЛО: http://example.com`);
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.ok(result.errors.some((error) => error.includes("КОРОТКИЙ ОПИС")));
  assert.ok(result.errors.some((error) => error.includes("Вага")));
  assert.ok(result.errors.some((error) => error.includes("Ціна продажу")));
  assert.ok(result.errors.some((error) => error.includes("MakerWorld")));
});

test("calculates the private floor and warns without blocking", () => {
  assert.deepEqual(calculatePrivatePriceGuidance(123, 450), {
    minimumPrice: 492,
    suggestedPrice: 500,
    belowMinimum: true,
  });
  assert.deepEqual(calculatePrivatePriceGuidance(null, 450), {
    minimumPrice: null,
    suggestedPrice: null,
    belowMinimum: false,
  });
});

test("builds one escaped Telegram caption without duplicated generated lines", () => {
  const caption = buildTelegramProductPost({
    title: "Тримач <Gen2>",
    telegramDescription: "Тримач <Gen2>\nЗручний у щоденному використанні.\n💰 500 грн\n📩 ЗАМОВИТИ\nNARADA DRUK",
    priceLabel: "500 грн",
    contactLink: "https://t.me/naradaprint",
    channelLink: "https://t.me/naradaprint",
  });
  assert.match(caption, /Тримач &lt;Gen2&gt;/);
  assert.equal((caption.match(/500 грн/g) ?? []).length, 1);
  assert.equal((caption.match(/ЗАМОВИТИ/g) ?? []).length, 1);
  assert.equal((caption.match(/NARADA DRUK/g) ?? []).length, 1);
  assert.ok(caption.length < 1024);
});

test("keeps a photo caption within the configured limit", () => {
  const caption = buildTelegramProductPost({
    title: "Компактний органайзер",
    telegramDescription: "Корисний опис. ".repeat(200),
    priceLabel: "600 грн",
    maximumLength: 1024,
  });
  assert.ok(caption.replace(/<[^>]*>/g, "").length <= 1024);
  assert.match(caption, /…/);
});
