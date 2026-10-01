import type { Prisma } from "@prisma/client";
import { calculatePromoDiscount, effectiveUnitPrice } from "./pricing";

export class OrderEditError extends Error {}

export const orderEditFields = {
  firstName: "Імʼя", lastName: "Прізвище", phone: "Телефон", telegramContact: "Telegram",
  cityName: "Місто", deliveryMethod: "Спосіб доставки", deliveryDestination: "Відділення / поштомат",
  courierAddress: "Адреса курʼєра", paymentMethod: "Оплата", comment: "Коментар клієнта",
  quantity: "Кількість", unitPrice: "Ціна ручної позиції", productTitle: "Назва ручної позиції",
} as const;
export type OrderEditField = keyof typeof orderEditFields;

export function parseOrderEditValue(field: OrderEditField, raw: string): string | number {
  const text = raw.trim();
  if (field === "quantity" || field === "unitPrice") {
    const maximum = field === "quantity" ? 20 : 1_000_000;
    if (!/^\d+$/.test(text) || Number(text) < 1 || Number(text) > maximum) {
      throw new OrderEditError(`Введіть ціле число від 1 до ${maximum}.`);
    }
    return Number(text);
  }
  if (field === "deliveryMethod") {
    const methods: Record<string, string> = { "відділення": "branch", "поштомат": "parcel_locker", "курʼєр": "courier", "кур'єр": "courier", "кур’єр": "courier" };
    const value = methods[text.toLocaleLowerCase("uk-UA")];
    if (!value) throw new OrderEditError("Введіть: відділення, поштомат або курʼєр.");
    return value;
  }
  if (field === "paymentMethod") {
    const methods: Record<string, string> = { "післяплата": "cash_on_delivery", "переказ": "transfer" };
    const value = methods[text.toLocaleLowerCase("uk-UA")];
    if (!value) throw new OrderEditError("Введіть: післяплата або переказ.");
    return value;
  }
  const value = text === "-" ? "" : text;
  const maximum = field === "comment" ? 1000 : field === "productTitle" ? 200 : 250;
  if (value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) throw new OrderEditError(`Введіть текст до ${maximum} символів одним рядком.`);
  if (["firstName", "productTitle"].includes(field) && !value) throw new OrderEditError("Це поле не може бути порожнім.");
  if (field === "phone" && value && (!/^\+?[\d ()-]{9,25}$/.test(value) || value.replace(/\D/g, "").length < 9)) throw new OrderEditError("Перевірте номер телефону.");
  return value;
}

export function editedOrderTotals(items: Array<{ regularUnitPrice: number; unitPrice: number; quantity: number }>, promoType: "percentage" | "fixed" | null, promoValue: number | null) {
  const subtotal = items.reduce((sum, item) => sum + item.regularUnitPrice * item.quantity, 0);
  const base = items.reduce((sum, item) => sum + item.unitPrice * item.quantity, 0);
  const discountAmount = promoType && promoValue !== null ? calculatePromoDiscount(base, promoType, promoValue) : 0;
  if (!Number.isSafeInteger(subtotal) || subtotal > 2_000_000_000) throw new OrderEditError("Сума замовлення завелика.");
  return { subtotal, saleDiscountAmount: subtotal - base, discountAmount, total: base - discountAmount };
}

export async function editOrder(transaction: Prisma.TransactionClient, input: {
  publicId: string; updatedAt: Date; field: OrderEditField; raw: string; itemId?: number;
}) {
  const value = parseOrderEditValue(input.field, input.raw);
  const order = await transaction.order.findUnique({ where: { publicId: input.publicId }, include: { items: true } });
  if (!order) throw new OrderEditError("Замовлення вже видалено.");
  if (order.updatedAt.getTime() !== input.updatedAt.getTime()) throw new OrderEditError("Замовлення вже змінилося. Відкрийте редагування знову.");
  let data: Prisma.OrderUpdateManyMutationInput;
  let itemUpdate: { id: number; data: Prisma.OrderItemUpdateInput } | null = null;
  if (["quantity", "unitPrice", "productTitle"].includes(input.field)) {
    const item = order.items.find((entry) => entry.id === input.itemId);
    if (!item) throw new OrderEditError("Позицію не знайдено.");
    const custom = order.source === "manual" && item.productId === null && !item.productSlug;
    if (input.field !== "quantity" && !custom) throw new OrderEditError("Ціна й назва каталожного товару визначаються каталогом.");
    if (input.field === "productTitle") {
      itemUpdate = { id: item.id, data: { productTitle: String(value) } };
      data = {};
    } else {
      const quantity = input.field === "quantity" ? Number(value) : item.quantity;
      let regularUnitPrice = input.field === "unitPrice" ? Number(value) : item.regularUnitPrice;
      let unitPrice = input.field === "unitPrice" ? Number(value) : item.unitPrice;
      if (!custom) {
        const product = item.productId ? await transaction.product.findUnique({ where: { id: item.productId }, include: { variants: true, category: true } }) : null;
        if (!product || product.status !== "published" || !product.category.isVisible) throw new OrderEditError("Товар уже недоступний. Кількість не змінено.");
        const variant = item.variantId ? product.variants.find((entry) => entry.id === item.variantId) : null;
        if ((item.variantId && !variant) || (product.variants.length && !variant)) throw new OrderEditError("Варіант товару вже недоступний.");
        const price = variant?.price ?? product.basePrice;
        if (price === null) throw new OrderEditError("Ціну товару потрібно уточнити.");
        regularUnitPrice = price;
        unitPrice = effectiveUnitPrice(product, price, !variant);
      } else if (!regularUnitPrice) regularUnitPrice = unitPrice;
      const changed = { quantity, regularUnitPrice, unitPrice, saleDiscountAmount: (regularUnitPrice - unitPrice) * quantity, totalPrice: unitPrice * quantity };
      itemUpdate = { id: item.id, data: changed };
      data = editedOrderTotals(order.items.map((entry) => entry.id === item.id ? changed : entry), order.promoTypeSnapshot, order.promoValueSnapshot);
    }
  } else {
    data = { [input.field]: value };
    if (input.field === "cityName") data.cityRef = "";
    if (["deliveryMethod", "deliveryDestination", "courierAddress"].includes(input.field)) data.destinationRef = "";
    if ((input.field === "phone" && !value && !order.telegramContact) || (input.field === "telegramContact" && !value && !order.phone)) throw new OrderEditError("Залиште хоча б один контакт клієнта.");
  }
  const result = await transaction.order.updateMany({ where: { id: order.id, updatedAt: input.updatedAt }, data: { ...data, updatedAt: new Date() } });
  if (result.count !== 1) throw new OrderEditError("Замовлення вже змінилося. Відкрийте редагування знову.");
  if (itemUpdate) await transaction.orderItem.update({ where: { id: itemUpdate.id }, data: itemUpdate.data });
  await transaction.orderEvent.create({ data: { orderId: order.id, eventType: "comment", toStatus: order.status, comment: `Змінено: ${orderEditFields[input.field]}${input.itemId ? ` (позиція ${order.items.findIndex((item) => item.id === input.itemId) + 1})` : ""}.`, actor: "telegram" } });
}
