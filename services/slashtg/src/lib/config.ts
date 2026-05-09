export type SlashUserKey = "userA" | "userB";

export type AllowedSlashUser = {
  keyName: SlashUserKey;
  telegramId: string;
  label: string;
};

export const animationTypes = ["soft-glow", "clouds", "sparkles", "tiny-faces"] as const;
export type AnimationTypeValue = (typeof animationTypes)[number];

export const prismaAnimationByUi: Record<AnimationTypeValue, string> = {
  "soft-glow": "soft_glow",
  clouds: "clouds",
  sparkles: "sparkles",
  "tiny-faces": "tiny_faces",
};

export const uiAnimationByPrisma: Record<string, AnimationTypeValue> = {
  soft_glow: "soft-glow",
  clouds: "clouds",
  sparkles: "sparkles",
  tiny_faces: "tiny-faces",
};

export function normalizeTelegramId(value?: string | number | null) {
  return String(value ?? "").trim();
}

export function getAllowedUsers(env: NodeJS.ProcessEnv = process.env): AllowedSlashUser[] {
  return [
    {
      keyName: "userA",
      telegramId: normalizeTelegramId(env.SLASHTG_USER_A_TELEGRAM_ID),
      label: String(env.SLASHTG_USER_A_LABEL || "Person A").trim() || "Person A",
    },
    {
      keyName: "userB",
      telegramId: normalizeTelegramId(env.SLASHTG_USER_B_TELEGRAM_ID),
      label: String(env.SLASHTG_USER_B_LABEL || "Person B").trim() || "Person B",
    },
  ];
}

export function findAllowedUserByTelegramId(
  telegramId: string,
  env: NodeJS.ProcessEnv = process.env,
) {
  const normalized = normalizeTelegramId(telegramId);
  if (!normalized) return null;
  return getAllowedUsers(env).find((user) => user.telegramId === normalized) ?? null;
}

export function getOtherUserKey(keyName: SlashUserKey): SlashUserKey {
  return keyName === "userA" ? "userB" : "userA";
}

export function normalizeAnimationType(value: unknown): AnimationTypeValue {
  const normalized = String(value || "").trim();
  return animationTypes.includes(normalized as AnimationTypeValue)
    ? (normalized as AnimationTypeValue)
    : "soft-glow";
}

export function normalizeMessage(value: unknown) {
  return String(value || "").replace(/\r\n/g, "\n").trim().slice(0, 800);
}

export function normalizeAvatarUrl(value: unknown) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  if (raw.length > 1000) {
    throw new Error("invalid_avatar_url");
  }

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("invalid_avatar_url");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("invalid_avatar_url");
  }

  return parsed.toString();
}
