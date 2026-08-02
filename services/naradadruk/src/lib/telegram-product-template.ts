export const telegramProductTemplate = `#товар
Назва: Настінне кріплення для навушників
Категорія: Інше
Ціна: 350 грн
Опис: Міцне кріплення для зручного зберігання навушників.
Матеріал: PETG
Термін: 1–3 дні
Доставка: Нова пошта або самовивіз
Оплата: Передплата на картку
Публікація: так`;

const fieldAliases = new Map<string, TemplateField>([
  ["назва", "title"],
  ["title", "title"],
  ["категорія", "category"],
  ["категория", "category"],
  ["category", "category"],
  ["ціна", "price"],
  ["цена", "price"],
  ["price", "price"],
  ["опис", "description"],
  ["description", "description"],
  ["матеріал", "material"],
  ["материал", "material"],
  ["material", "material"],
  ["термін", "leadTime"],
  ["срок", "leadTime"],
  ["lead time", "leadTime"],
  ["доставка", "delivery"],
  ["delivery", "delivery"],
  ["оплата", "payment"],
  ["payment", "payment"],
  ["варіанти", "variants"],
  ["варианты", "variants"],
  ["variants", "variants"],
  ["публікація", "publication"],
  ["публикация", "publication"],
  ["publication", "publication"],
]);

type TemplateField =
  | "title"
  | "category"
  | "price"
  | "description"
  | "material"
  | "leadTime"
  | "delivery"
  | "payment"
  | "variants"
  | "publication";

export type ParsedTelegramProduct = {
  title: string;
  category: string;
  basePrice: number | null;
  priceFrom: boolean;
  description: string;
  material: string;
  leadTime: string;
  delivery: string;
  payment: string;
  variants: Array<{ label: string; price: number; priceFrom: boolean }>;
  shouldPublish: boolean;
};

export type TelegramTemplateParseResult =
  | { matched: false }
  | { matched: true; ok: false; errors: string[] }
  | { matched: true; ok: true; product: ParsedTelegramProduct };

function normalizeText(value: string) {
  return value
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function parsePrice(value: string) {
  const match = value.match(
    /(?:^|\s)(від\s+|от\s+|from\s+)?(\d[\d\s.,]*)\s*(?:грн|₴|uah)(?=$|\s|[.,!?])/iu,
  );

  if (!match) {
    return null;
  }

  const amount = Number(match[2].replace(/[^\d]/g, ""));

  if (!Number.isSafeInteger(amount) || amount < 0) {
    return null;
  }

  return {
    amount,
    priceFrom: Boolean(match[1]),
  };
}

function parseVariant(line: string) {
  const match = line.match(
    /^\s*(?:[-–—•]\s*)?(.+?)\s+(?:—|–|-|:)\s*(від\s+|от\s+|from\s+)?(\d[\d\s.,]*)\s*(?:грн|₴|uah)\s*$/iu,
  );

  if (!match) {
    return null;
  }

  const price = Number(match[3].replace(/[^\d]/g, ""));

  if (!Number.isSafeInteger(price) || price < 0) {
    return null;
  }

  return {
    label: match[1].trim(),
    price,
    priceFrom: Boolean(match[2]),
  };
}

function isAffirmative(value: string) {
  return /^(так|да|yes|опублікувати|опубликовать|publish|\+)$/iu.test(value.trim());
}

export function parseTelegramProductTemplate(source: string): TelegramTemplateParseResult {
  const text = normalizeText(source);

  if (!/(?:^|\s)#товар(?=$|\s|[.,!?])/iu.test(text)) {
    return { matched: false };
  }

  const values = new Map<TemplateField, string[]>();
  let activeField: TemplateField | null = null;

  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();

    if (!line || /^#товар(?=$|\s|[.,!?])/iu.test(line)) {
      continue;
    }

    const fieldMatch = line.match(/^([^:]{2,30}):\s*(.*)$/u);
    const resolvedField = fieldMatch
      ? fieldAliases.get(fieldMatch[1].trim().toLocaleLowerCase("uk-UA"))
      : undefined;

    if (resolvedField && fieldMatch) {
      activeField = resolvedField;
      values.set(activeField, fieldMatch[2].trim() ? [fieldMatch[2].trim()] : []);
      continue;
    }

    if (activeField) {
      values.set(activeField, [...(values.get(activeField) ?? []), line]);
    }
  }

  const value = (field: TemplateField) => (values.get(field) ?? []).join("\n").trim();
  const title = value("title");
  const category = value("category");
  const description = value("description");
  const parsedPrice = parsePrice(value("price"));
  const variantLines = values.get("variants") ?? [];
  const variants = variantLines.map(parseVariant).filter((variant) => variant !== null);
  const errors: string[] = [];

  if (title.length < 3) {
    errors.push("Додайте поле «Назва».");
  }

  if (!category) {
    errors.push("Додайте поле «Категорія».");
  }

  if (description.length < 8) {
    errors.push("Додайте змістовне поле «Опис».");
  }

  if (!parsedPrice && variants.length === 0) {
    errors.push("Додайте «Ціна» або хоча б один рядок у «Варіанти».");
  }

  if (variantLines.length > variants.length) {
    errors.push("Формат варіанту: «Назва — 350 грн».");
  }

  if (errors.length > 0) {
    return { matched: true, ok: false, errors };
  }

  return {
    matched: true,
    ok: true,
    product: {
      title,
      category,
      basePrice: parsedPrice?.amount ?? null,
      priceFrom: parsedPrice?.priceFrom ?? false,
      description,
      material: value("material"),
      leadTime: value("leadTime"),
      delivery: value("delivery"),
      payment: value("payment"),
      variants,
      shouldPublish: isAffirmative(value("publication")),
    },
  };
}
