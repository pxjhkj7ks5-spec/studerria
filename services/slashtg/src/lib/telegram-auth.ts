import { createHmac, timingSafeEqual } from "node:crypto";

export type TelegramUser = {
  id: number | string;
  first_name?: string;
  last_name?: string;
  username?: string;
  language_code?: string;
  photo_url?: string;
};

export type ValidatedTelegramInitData = {
  user: TelegramUser;
  authDate: number;
  queryId?: string;
  startParam?: string;
};

export type ValidateInitDataOptions = {
  botToken: string;
  maxAgeSeconds?: number;
  nowSeconds?: number;
};

function hmacSha256(key: string | Buffer, value: string) {
  return createHmac("sha256", key).update(value).digest();
}

export function buildDataCheckString(initData: string) {
  const params = new URLSearchParams(initData);
  const rows: string[] = [];

  params.forEach((value, key) => {
    if (key === "hash") return;
    rows.push(`${key}=${value}`);
  });

  return rows.sort().join("\n");
}

export function validateTelegramInitData(
  initData: string,
  options: ValidateInitDataOptions,
): ValidatedTelegramInitData {
  const botToken = String(options.botToken || "").trim();
  if (!botToken) {
    throw new Error("missing_bot_token");
  }

  const params = new URLSearchParams(initData);
  const receivedHash = params.get("hash") || "";
  if (!receivedHash) {
    throw new Error("missing_hash");
  }

  const dataCheckString = buildDataCheckString(initData);
  const secretKey = hmacSha256("WebAppData", botToken);
  const expectedHash = createHmac("sha256", secretKey).update(dataCheckString).digest("hex");

  const expected = Buffer.from(expectedHash, "hex");
  const received = Buffer.from(receivedHash, "hex");
  if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
    throw new Error("invalid_hash");
  }

  const authDate = Number(params.get("auth_date") || 0);
  if (!Number.isFinite(authDate) || authDate <= 0) {
    throw new Error("missing_auth_date");
  }

  const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const maxAgeSeconds = Number(options.maxAgeSeconds || 86400);
  if (maxAgeSeconds > 0 && nowSeconds - authDate > maxAgeSeconds) {
    throw new Error("expired_init_data");
  }

  const rawUser = params.get("user");
  if (!rawUser) {
    throw new Error("missing_user");
  }

  let user: TelegramUser;
  try {
    user = JSON.parse(rawUser) as TelegramUser;
  } catch {
    throw new Error("invalid_user");
  }

  if (!user || String(user.id || "").trim() === "") {
    throw new Error("invalid_user");
  }

  return {
    user,
    authDate,
    queryId: params.get("query_id") || undefined,
    startParam: params.get("start_param") || undefined,
  };
}

export function signTelegramInitDataForTest(
  fields: Record<string, string>,
  botToken: string,
) {
  const params = new URLSearchParams(fields);
  const dataCheckString = buildDataCheckString(params.toString());
  const secretKey = hmacSha256("WebAppData", botToken);
  const hash = createHmac("sha256", secretKey).update(dataCheckString).digest("hex");
  params.set("hash", hash);
  return params.toString();
}
