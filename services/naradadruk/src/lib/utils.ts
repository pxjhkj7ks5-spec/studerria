const transliterationMap: Record<string, string> = {
  а: "a",
  б: "b",
  в: "v",
  г: "h",
  ґ: "g",
  д: "d",
  е: "e",
  є: "ye",
  ж: "zh",
  з: "z",
  и: "y",
  і: "i",
  ї: "yi",
  й: "i",
  к: "k",
  л: "l",
  м: "m",
  н: "n",
  о: "o",
  п: "p",
  р: "r",
  с: "s",
  т: "t",
  у: "u",
  ф: "f",
  х: "kh",
  ц: "ts",
  ч: "ch",
  ш: "sh",
  щ: "shch",
  ь: "",
  ю: "yu",
  я: "ya",
};

export function slugify(value: string) {
  const transliterated = value
    .trim()
    .toLowerCase()
    .split("")
    .map((char) => transliterationMap[char] ?? char)
    .join("");

  const normalized = transliterated
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");

  return normalized || `item-${Date.now()}`;
}

export function formatPrice(value?: number | null) {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "Ціна за запитом";
  }

  return `${new Intl.NumberFormat("uk-UA").format(value)} грн`;
}

export function parseOptionalInt(value: FormDataEntryValue | null) {
  const normalized = String(value ?? "").trim();

  if (!normalized) {
    return null;
  }

  const parsed = Number(normalized);
  return Number.isFinite(parsed) ? Math.round(parsed) : null;
}

export function parseCheckbox(value: FormDataEntryValue | null) {
  return String(value ?? "") === "on";
}

export function ensureArray<T>(value: T | T[] | null | undefined) {
  if (Array.isArray(value)) {
    return value;
  }

  return value == null ? [] : [value];
}
