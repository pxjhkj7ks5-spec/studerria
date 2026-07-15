import { createHmac, timingSafeEqual } from "node:crypto";

export function validateTelegramInitData(initData, { botToken, maxAgeSeconds = 86_400, now = Date.now() } = {}) {
  if (!botToken) throw new Error("Telegram auth is not configured.");
  const params = new URLSearchParams(String(initData || ""));
  const hash = params.get("hash") || "";
  params.delete("hash");
  const entries = [...params.entries()].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  const checkStrings = [entries, entries.filter(([key]) => key !== "signature")]
    .map((items) => items.map(([key, value]) => `${key}=${value}`).join("\n"));
  const secret = createHmac("sha256", "WebAppData").update(botToken).digest();
  const validHash = checkStrings.some((checkString) => {
    const expected = createHmac("sha256", secret).update(checkString).digest("hex");
    return Boolean(hash) && hash.length === expected.length && timingSafeEqual(Buffer.from(hash), Buffer.from(expected));
  });
  if (!validHash) throw new Error("Telegram initData signature is invalid.");
  const authDate = Number(params.get("auth_date") || 0);
  if (!authDate || Math.abs(now / 1000 - authDate) > maxAgeSeconds) throw new Error("Telegram initData has expired.");
  const user = JSON.parse(params.get("user") || "{}");
  if (!Number.isSafeInteger(user.id)) throw new Error("Telegram user is missing.");
  return user;
}
