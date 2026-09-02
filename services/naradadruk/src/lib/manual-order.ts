export type ManualOrderStep =
  | "name"
  | "phone"
  | "telegram"
  | "delivery"
  | "kind"
  | "catalog"
  | "unique_description"
  | "unique_price"
  | "confirm";

export type ManualCatalogItem = {
  productId: number;
  productSlug: string;
  productTitle: string;
  productUrl: string;
  variantId: number | null;
  variantLabel: string;
  unitPrice: number;
  regularUnitPrice: number;
};

type ManualOrderSelection =
  | { kind: "catalog"; items: Array<ManualCatalogItem & { quantity: number }> }
  | { kind: "unique"; description: string; agreedPrice: number };

export type ManualOrderSession = {
  step: ManualOrderStep;
  customerName: string;
  phone: string;
  telegramContact: string;
  deliveryText: string;
  uniqueDescription: string;
  selection: ManualOrderSelection | null;
};

type ManualOrderTextResult =
  | { ok: true; session: ManualOrderSession }
  | { ok: false; error: string };

function cleanText(value: string, maximumLength: number) {
  return value
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim()
    .slice(0, maximumLength);
}

export function createManualOrderSession(): ManualOrderSession {
  return {
    step: "name",
    customerName: "",
    phone: "",
    telegramContact: "",
    deliveryText: "",
    uniqueDescription: "",
    selection: null,
  };
}

export function applyManualOrderText(
  current: ManualOrderSession,
  rawValue: string,
): ManualOrderTextResult {
  const session = { ...current };

  if (session.step === "name") {
    const customerName = cleanText(rawValue, 120);
    if (customerName.length < 2) return { ok: false, error: "Вкажіть імʼя клієнта (щонайменше 2 символи)." };
    session.customerName = customerName;
    session.step = "phone";
    return { ok: true, session };
  }

  if (session.step === "phone") {
    const phone = cleanText(rawValue, 22);
    if (!/^\+?[\d\s()\-]{9,22}$/.test(phone)) return { ok: false, error: "Вкажіть коректний номер телефону." };
    session.phone = phone;
    session.step = "telegram";
    return { ok: true, session };
  }

  if (session.step === "telegram") {
    const telegramContact = cleanText(rawValue, 80);
    if (!/^@?[a-zA-Z0-9_+().\-\s]{3,80}$/.test(telegramContact)) {
      return { ok: false, error: "Вкажіть Telegram username або номер телефону." };
    }
    session.telegramContact = telegramContact;
    session.step = "delivery";
    return { ok: true, session };
  }

  if (session.step === "delivery") {
    const deliveryText = cleanText(rawValue, 240);
    if (deliveryText.length < 3) return { ok: false, error: "Вкажіть відділення або адресу Нової пошти." };
    session.deliveryText = deliveryText;
    session.step = "kind";
    return { ok: true, session };
  }

  if (session.step === "unique_description") {
    const uniqueDescription = cleanText(rawValue, 500);
    if (uniqueDescription.length < 3) return { ok: false, error: "Опис унікального замовлення закороткий." };
    session.uniqueDescription = uniqueDescription;
    session.step = "unique_price";
    return { ok: true, session };
  }

  if (session.step === "unique_price") {
    const agreedPrice = Number(rawValue.replace(/\s|грн/gi, ""));
    if (!Number.isInteger(agreedPrice) || agreedPrice < 1 || agreedPrice > 10_000_000) {
      return { ok: false, error: "Вкажіть погоджену цілу ціну від 1 до 10 000 000 грн." };
    }
    session.selection = { kind: "unique", description: session.uniqueDescription, agreedPrice };
    session.step = "confirm";
    return { ok: true, session };
  }

  return { ok: false, error: "Завершіть поточний крок кнопками в попередньому повідомленні." };
}

export function chooseManualOrderKind(
  current: ManualOrderSession,
  kind: "catalog" | "unique",
) {
  if (current.step !== "kind") return current;
  return {
    ...current,
    step: kind === "catalog" ? "catalog" as const : "unique_description" as const,
    selection: kind === "catalog" ? { kind: "catalog" as const, items: [] } : null,
  };
}

export function selectManualCatalogItem(
  current: ManualOrderSession,
  item: ManualCatalogItem,
) {
  if (current.step !== "catalog") return current;
  const selectedItems = current.selection?.kind === "catalog" ? current.selection.items : [];
  const existingIndex = selectedItems.findIndex((selected) =>
    selected.productId === item.productId && selected.variantId === item.variantId,
  );
  const items = existingIndex === -1
    ? [...selectedItems, { ...item, quantity: 1 }]
    : selectedItems.map((selected, index) => index === existingIndex
        ? { ...item, quantity: Math.min(selected.quantity + 1, 99) }
        : selected);
  return {
    ...current,
    selection: { kind: "catalog" as const, items },
  };
}

export function removeManualCatalogItem(
  current: ManualOrderSession,
  productId: number,
  variantId: number | null,
) {
  if (current.selection?.kind !== "catalog" || !["catalog", "confirm"].includes(current.step)) return current;
  const items = current.selection.items.flatMap((selected) => {
    if (selected.productId !== productId || selected.variantId !== variantId) return [selected];
    return selected.quantity > 1 ? [{ ...selected, quantity: selected.quantity - 1 }] : [];
  });
  return {
    ...current,
    step: items.length > 0 ? current.step : "catalog" as const,
    selection: { kind: "catalog" as const, items },
  };
}

export function completeManualCatalogSelection(current: ManualOrderSession) {
  if (current.step !== "catalog" || current.selection?.kind !== "catalog" || current.selection.items.length === 0) {
    return current;
  }
  return { ...current, step: "confirm" as const };
}

export function continueManualCatalogSelection(current: ManualOrderSession) {
  if (current.step !== "confirm" || current.selection?.kind !== "catalog") return current;
  return { ...current, step: "catalog" as const };
}

export function buildManualOrderCreateData(session: ManualOrderSession, publicId: string) {
  if (session.step !== "confirm" || !session.selection) {
    throw new Error("Ручне замовлення ще не готове до створення.");
  }

  const [firstName, ...lastNameParts] = session.customerName.split(/\s+/);
  const items = session.selection.kind === "catalog"
    ? session.selection.items.map((item) => ({
        productId: item.productId,
        productSlug: item.productSlug,
        productTitle: item.productTitle,
        productUrl: item.productUrl,
        variantId: item.variantId,
        variantLabel: item.variantLabel,
        quantity: item.quantity,
        unitPrice: item.unitPrice,
        regularUnitPrice: item.regularUnitPrice,
        saleDiscountAmount: (item.regularUnitPrice - item.unitPrice) * item.quantity,
        totalPrice: item.unitPrice * item.quantity,
      }))
    : [{
        productSlug: "",
        productTitle: session.selection.description,
        productUrl: "",
        variantLabel: "",
        quantity: 1,
        unitPrice: session.selection.agreedPrice,
        regularUnitPrice: session.selection.agreedPrice,
        saleDiscountAmount: 0,
        totalPrice: session.selection.agreedPrice,
      }];
  if (items.length === 0) throw new Error("Додайте хоча б один товар із каталогу.");
  const subtotal = items.reduce((sum, item) => sum + item.regularUnitPrice * item.quantity, 0);
  const saleDiscountAmount = items.reduce((sum, item) => sum + item.saleDiscountAmount, 0);

  return {
    publicId,
    source: "manual" as const,
    firstName,
    lastName: lastNameParts.join(" "),
    comment: "",
    phone: session.phone,
    telegramContact: session.telegramContact,
    cityName: "",
    cityRef: "",
    deliveryMethod: "branch" as const,
    deliveryDestination: session.deliveryText,
    destinationRef: "",
    courierAddress: "",
    paymentMethod: "transfer" as const,
    subtotal,
    saleDiscountAmount,
    discountAmount: 0,
    total: subtotal - saleDiscountAmount,
    notificationStatus: "skipped" as const,
    items: { create: items },
    events: {
      create: {
        eventType: "created",
        toStatus: "new",
        comment: "Створено власником у Telegram",
        actor: "telegram",
      },
    },
  };
}
