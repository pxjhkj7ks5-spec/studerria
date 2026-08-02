export const productContentPackageTemplate = `НАЗВА:
КАТЕГОРІЯ:
КОРОТКИЙ ОПИС:
ОПИС ДЛЯ САЙТУ:
ДЛЯ КОГО:
ПЕРЕВАГИ:
- ...
ХАРАКТЕРИСТИКИ:
- ...
СУМІСНІСТЬ:
КОМПЛЕКТАЦІЯ:
ТЕКСТ TELEGRAM:
МАТЕРІАЛ:
ТЕРМІН:
ВАГА, Г:
ЦІНА ПРОДАЖУ:
ДЖЕРЕЛО:
АВТОР МОДЕЛІ:
ЛІЦЕНЗІЯ:`;

type PackageField =
  | "title"
  | "category"
  | "shortDescription"
  | "fullDescription"
  | "useCaseNote"
  | "benefitsNote"
  | "specificationsNote"
  | "compatibilityNote"
  | "packageContentsNote"
  | "telegramDescription"
  | "materialNote"
  | "leadTime"
  | "printWeightGrams"
  | "price"
  | "sourceModelUrl"
  | "sourceModelAuthor"
  | "sourceModelLicense";

export type ProductContentPackage = {
  title: string;
  category: string;
  shortDescription: string;
  fullDescription: string;
  useCaseNote: string;
  benefitsNote: string;
  specificationsNote: string;
  compatibilityNote: string;
  packageContentsNote: string;
  telegramDescription: string;
  materialNote: string;
  leadTime: string;
  printWeightGrams: number | null;
  price: number | null;
  sourceModelUrl: string;
  sourceModelAuthor: string;
  sourceModelLicense: string;
};

export type ProductContentPackageParseResult =
  | { ok: false; errors: string[]; warnings: string[] }
  | { ok: true; product: ProductContentPackage; warnings: string[] };

const fieldAliases = new Map<string, PackageField>([
  ["назва", "title"],
  ["категорія", "category"],
  ["короткий опис", "shortDescription"],
  ["опис для сайту", "fullDescription"],
  ["для кого", "useCaseNote"],
  ["переваги", "benefitsNote"],
  ["характеристики", "specificationsNote"],
  ["сумісність", "compatibilityNote"],
  ["комплектація", "packageContentsNote"],
  ["текст telegram", "telegramDescription"],
  ["telegram", "telegramDescription"],
  ["матеріал", "materialNote"],
  ["термін", "leadTime"],
  ["вага, г", "printWeightGrams"],
  ["вага г", "printWeightGrams"],
  ["ціна продажу", "price"],
  ["ціна", "price"],
  ["джерело", "sourceModelUrl"],
  ["автор моделі", "sourceModelAuthor"],
  ["ліцензія", "sourceModelLicense"],
]);

function normalizeText(value: string) {
  return value
    .replace(/\u00a0/g, " ")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function normalizeHeading(value: string) {
  return value.trim().replace(/\s+/g, " ").toLocaleLowerCase("uk-UA");
}

function isUnknownPackageHeading(value: string) {
  const letters = value.replace(/[^A-Za-zА-Яа-яІіЇїЄєҐґ]/g, "");
  return letters.length >= 3 && value === value.toLocaleUpperCase("uk-UA");
}

function optionalInteger(value: string, label: string, maximum: number, errors: string[]) {
  const normalized = value.trim();
  if (!normalized || /^(?:невідомо|невідомий|немає|—|-)$/iu.test(normalized)) return null;
  const digits = normalized.replace(/\s/g, "").match(/^([0-9]+)(?:г|грн|₴)?$/iu)?.[1];
  const parsed = digits ? Number(digits) : Number.NaN;
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || parsed > maximum) {
    errors.push(`${label} має бути додатним цілим числом або «невідомо».`);
    return null;
  }
  return parsed;
}

function isMakerWorldUrl(value: string) {
  if (!value) return true;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && /(?:^|\.)makerworld\.com$/iu.test(url.hostname);
  } catch {
    return false;
  }
}

export function parseProductContentPackage(source: string): ProductContentPackageParseResult {
  const values = new Map<PackageField, string[]>();
  const warnings: string[] = [];
  let activeField: PackageField | null = null;

  for (const rawLine of normalizeText(source).split("\n")) {
    const line = rawLine.trim();
    if (!line) {
      if (activeField && (values.get(activeField)?.length ?? 0) > 0) {
        values.set(activeField, [...(values.get(activeField) ?? []), ""]);
      }
      continue;
    }

    const fieldMatch = line.match(/^([^:]{2,60}):\s*(.*)$/u);
    const heading = fieldMatch ? fieldMatch[1].trim() : "";
    const resolvedField = fieldMatch ? fieldAliases.get(normalizeHeading(heading)) : undefined;
    if (fieldMatch && resolvedField) {
      activeField = resolvedField;
      values.set(resolvedField, fieldMatch[2].trim() ? [fieldMatch[2].trim()] : []);
      continue;
    }
    if (fieldMatch && isUnknownPackageHeading(heading)) {
      warnings.push(`Невідоме поле «${heading}» пропущено.`);
      activeField = null;
      continue;
    }
    if (activeField) values.set(activeField, [...(values.get(activeField) ?? []), line]);
  }

  const value = (field: PackageField) => normalizeText((values.get(field) ?? []).join("\n"));
  const errors: string[] = [];
  const title = value("title");
  const shortDescription = value("shortDescription");
  const fullDescription = value("fullDescription");
  const telegramDescription = value("telegramDescription");
  const sourceModelUrl = value("sourceModelUrl");

  if (title.length < 3) errors.push("Заповніть «НАЗВА» щонайменше трьома символами.");
  if (shortDescription.length < 8) errors.push("Заповніть «КОРОТКИЙ ОПИС» щонайменше вісьмома символами.");
  if (fullDescription.length < 20) errors.push("Заповніть «ОПИС ДЛЯ САЙТУ» щонайменше двадцятьма символами.");
  if (telegramDescription.length < 10) errors.push("Заповніть «ТЕКСТ TELEGRAM» щонайменше десятьма символами.");
  if (!isMakerWorldUrl(sourceModelUrl)) errors.push("«ДЖЕРЕЛО» має бути публічним HTTPS-посиланням MakerWorld.");

  const printWeightGrams = optionalInteger(value("printWeightGrams"), "Вага", 1_000_000, errors);
  const price = optionalInteger(value("price"), "Ціна продажу", 10_000_000, errors);
  if (errors.length > 0) return { ok: false, errors, warnings };

  return {
    ok: true,
    warnings,
    product: {
      title,
      category: value("category"),
      shortDescription,
      fullDescription,
      useCaseNote: value("useCaseNote"),
      benefitsNote: value("benefitsNote"),
      specificationsNote: value("specificationsNote"),
      compatibilityNote: value("compatibilityNote"),
      packageContentsNote: value("packageContentsNote"),
      telegramDescription,
      materialNote: value("materialNote"),
      leadTime: value("leadTime"),
      printWeightGrams,
      price,
      sourceModelUrl,
      sourceModelAuthor: value("sourceModelAuthor"),
      sourceModelLicense: value("sourceModelLicense"),
    },
  };
}

export function calculatePrivatePriceGuidance(printWeightGrams: number | null, price: number | null) {
  if (printWeightGrams === null) {
    return { minimumPrice: null, suggestedPrice: null, belowMinimum: false };
  }
  const minimumPrice = printWeightGrams * 4;
  const suggestedPrice = Math.ceil(minimumPrice / 10) * 10;
  return {
    minimumPrice,
    suggestedPrice,
    belowMinimum: price !== null && price < minimumPrice,
  };
}

function escapeHtml(value: string) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function withoutGeneratedTelegramLines(value: string, title: string) {
  const normalizedTitle = title.trim().toLocaleLowerCase("uk-UA");
  return normalizeText(value)
    .split("\n")
    .filter((line) => {
      const normalized = line.replace(/^[-–—•✦🧩]\s*/u, "").trim().toLocaleLowerCase("uk-UA");
      if (!normalized) return true;
      if (normalized === normalizedTitle) return false;
      if (/^(?:💰\s*)?(?:ціна\s*:?\s*)?(?:від\s+)?\d[\d\s]*(?:грн|₴|uah)(?=$|\s|[.,!?])/iu.test(line.trim())) return false;
      if (/^(?:📩\s*)?(?:замовити|зробити замовлення)(?=$|\s|[.,!?])/iu.test(line.trim())) return false;
      if (/^(?:✦\s*)?narada\s+druk\s*$/iu.test(line.trim())) return false;
      return true;
    })
    .join("\n")
    .trim();
}

function visibleLength(value: string) {
  return value.replace(/<[^>]*>/g, "").length;
}

export function buildTelegramProductPost(input: {
  title: string;
  telegramDescription: string;
  priceLabel: string;
  contactLink?: string;
  channelLink?: string;
  maximumLength?: number;
}) {
  const maximumLength = input.maximumLength ?? 1024;
  let body = withoutGeneratedTelegramLines(input.telegramDescription, input.title);
  const assemble = () => {
    const lines = [`✦ <b>${escapeHtml(input.title)}</b>`, ""];
    if (body) lines.push(escapeHtml(body), "");
    lines.push(`💰 <b>${escapeHtml(input.priceLabel)}</b>`, "");
    lines.push(
      input.contactLink
        ? `📩 <a href="${escapeHtml(input.contactLink)}"><b>ЗАМОВИТИ</b></a>`
        : "📩 <b>ЗАМОВИТИ</b>",
    );
    if (input.channelLink) {
      lines.push(`✦ <a href="${escapeHtml(input.channelLink)}"><b>NARADA DRUK</b></a>`);
    }
    return lines.join("\n");
  };

  let result = assemble();
  const overflow = visibleLength(result) - maximumLength;
  if (overflow > 0 && body.length > 0) {
    body = `${body.slice(0, Math.max(0, body.length - overflow - 1)).trimEnd()}…`;
    result = assemble();
  }
  if (visibleLength(result) > maximumLength) {
    throw new Error(`Telegram-підпис перевищує ${maximumLength} символи навіть без опису.`);
  }
  return result;
}
