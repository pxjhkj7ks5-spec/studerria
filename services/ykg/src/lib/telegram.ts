import { defaultTelegramUrl } from "@/lib/constants";

export type TelegramIntent = "product" | "custom" | "catalog";

type TelegramLinkInput = {
  baseUrl?: string | null;
  intent: TelegramIntent;
  productTitle?: string;
  productUrl?: string;
  variantLabel?: string;
};

function extractTelegramUsername(value?: string | null) {
  const fallbackUsername = "youngkillersgroup_store";
  const rawValue = value?.trim() || defaultTelegramUrl;

  try {
    const url = new URL(rawValue);

    if (url.hostname === "t.me" || url.hostname === "telegram.me") {
      return url.pathname.split("/").filter(Boolean)[0] || fallbackUsername;
    }

    if (url.hostname === "web.telegram.org") {
      const match = url.hash.match(/@([a-zA-Z0-9_]+)/);
      return match?.[1] || fallbackUsername;
    }
  } catch {
    const match = rawValue.match(/@([a-zA-Z0-9_]+)/);
    return match?.[1] || fallbackUsername;
  }

  return fallbackUsername;
}

function buildDraftMessage(input: TelegramLinkInput) {
  if (input.intent === "custom") {
    return "Вітаю! Хочу замовити індивідуальний 3D-друк. Надішлю опис, розміри або фото прикладу.";
  }

  if (input.intent === "product" && input.productTitle) {
    const variant = input.variantLabel ? `, варіант «${input.variantLabel}»` : "";
    const productUrl = input.productUrl ? `\n${input.productUrl}` : "";

    return `Вітаю! Хочу замовити «${input.productTitle}»${variant}. Підкажіть, будь ласка, щодо терміну та наявності.${productUrl}`;
  }

  return "Вітаю! Хочу уточнити асортимент YKG і підібрати готовий виріб.";
}

export function buildTelegramLink(input: TelegramLinkInput) {
  const username = extractTelegramUsername(input.baseUrl);
  const draft = buildDraftMessage(input);
  const url = new URL(`https://t.me/${username}`);

  url.searchParams.set("text", draft);
  return url.toString();
}
