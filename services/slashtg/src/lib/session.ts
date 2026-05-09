import { createHmac, timingSafeEqual } from "node:crypto";
import type { SlashUserKey } from "@/lib/config";

export const slashSessionCookieName = "slashtg_session";
export const slashSessionMaxAgeSeconds = 60 * 60 * 24 * 30;

export type SlashSession = {
  keyName: SlashUserKey;
  telegramId: string;
  issuedAt: number;
};

function getSecret() {
  const secret = String(process.env.SLASHTG_SESSION_SECRET || "").trim();
  if (!secret) {
    throw new Error("missing_session_secret");
  }
  return secret;
}

function signPayload(payload: string) {
  return createHmac("sha256", getSecret()).update(payload).digest("base64url");
}

export function createSessionToken(session: SlashSession) {
  const payload = Buffer.from(JSON.stringify(session), "utf8").toString("base64url");
  return `${payload}.${signPayload(payload)}`;
}

export function parseSessionToken(token?: string | null): SlashSession | null {
  const raw = String(token || "");
  const [payload, signature] = raw.split(".");
  if (!payload || !signature) return null;

  const expected = Buffer.from(signPayload(payload));
  const received = Buffer.from(signature);
  if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
    return null;
  }

  let parsed: SlashSession;
  try {
    parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as SlashSession;
  } catch {
    return null;
  }

  if (
    (parsed.keyName !== "userA" && parsed.keyName !== "userB") ||
    !parsed.telegramId ||
    !Number.isFinite(Number(parsed.issuedAt))
  ) {
    return null;
  }

  const ageSeconds = Math.floor(Date.now() / 1000) - Number(parsed.issuedAt);
  if (ageSeconds > slashSessionMaxAgeSeconds) {
    return null;
  }

  return parsed;
}
