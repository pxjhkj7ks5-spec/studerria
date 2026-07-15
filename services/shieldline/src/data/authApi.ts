import { getTelegramInitData } from "../platform/telegramShell";

export type TelegramProfile = {
  id: string;
  username?: string | null;
  firstName?: string | null;
  lastName?: string | null;
  languageCode?: string | null;
};

export type AuthProfile = {
  id: string;
  nickname: string | null;
  displayName: string;
  platform: string;
  registrationCompleted: boolean;
  registrationCompletedAt: string | null;
  consentVersion: string | null;
  consentAcceptedAt: string | null;
  telegram: TelegramProfile | null;
  deviceCount: number;
};

export type AuthBootstrap = {
  status: "authenticated" | "onboarding_required";
  authRequired: boolean;
  consentVersion: string;
  user: AuthProfile;
  telegramPrefill: TelegramProfile | null;
  telegramLinkOffer: boolean;
  telegramConflict: boolean;
};

const DEVICE_TOKEN_KEY = "shieldline-device-token-v1";

function base64Url(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function getDeviceToken() {
  const existing = window.localStorage.getItem(DEVICE_TOKEN_KEY);
  if (existing) return existing;
  const bytes = new Uint8Array(32);
  window.crypto.getRandomValues(bytes);
  const token = base64Url(bytes);
  window.localStorage.setItem(DEVICE_TOKEN_KEY, token);
  return token;
}

async function request<T>(path: string, body: Record<string, unknown> = {}) {
  const response = await fetch(`${import.meta.env.BASE_URL}api${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({})) as T & { error?: string };
  if (!response.ok) throw new Error(payload.error || "Не вдалося зв’язатися із ShieldLine.");
  return payload;
}

async function telegramInitData() {
  return (await getTelegramInitData()) || undefined;
}

export const authApi = {
  async bootstrap(): Promise<AuthBootstrap> {
    return request("/auth/bootstrap", { deviceToken: getDeviceToken(), telegramInitData: await telegramInitData() });
  },
  async nicknameAvailability(nickname: string) {
    return request<{ nickname: string; available: boolean }>("/auth/nickname-availability", { nickname });
  },
  async register(nickname: string, consentVersion: string) {
    return request<{ user: AuthProfile; consentVersion: string }>("/auth/register", {
      nickname,
      consentVersion,
      consentAccepted: true,
      deviceToken: getDeviceToken(),
      telegramInitData: await telegramInitData(),
    });
  },
  async generateTransferCode() {
    return request<{ code: string; expiresAt: string }>("/auth/transfer-code");
  },
  async redeemTransferCode(code: string) {
    return request<{ user: AuthProfile; consentVersion: string }>("/auth/redeem-code", {
      code,
      deviceToken: getDeviceToken(),
      telegramInitData: await telegramInitData(),
    });
  },
  async linkTelegram() {
    const initData = await telegramInitData();
    if (!initData) throw new Error("Відкрийте ShieldLine всередині Telegram, щоб прив’язати акаунт.");
    return request<{ user: AuthProfile }>("/auth/link-telegram", { telegramInitData: initData });
  },
};
