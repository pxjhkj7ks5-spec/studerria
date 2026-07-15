import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import { validateTelegramInitData } from "../serverTelegramAuth.mjs";

const botToken = "123456:test-token";
const now = Date.UTC(2026, 6, 15, 10, 0, 0);

function signedInitData({ includeSignatureInHash }) {
  const params = new URLSearchParams({
    auth_date: String(now / 1000),
    query_id: "query-1",
    signature: "telegram-ed25519-signature",
    user: JSON.stringify({ id: 42, username: "sokil" }),
  });
  const entries = [...params.entries()]
    .filter(([key]) => includeSignatureInHash || key !== "signature")
    .sort(([left], [right]) => left.localeCompare(right));
  const checkString = entries.map(([key, value]) => `${key}=${value}`).join("\n");
  const secret = createHmac("sha256", "WebAppData").update(botToken).digest();
  params.set("hash", createHmac("sha256", secret).update(checkString).digest("hex"));
  return params.toString();
}

test("Telegram validation accepts current signature fields without weakening the bot-token hash", () => {
  assert.equal(validateTelegramInitData(signedInitData({ includeSignatureInHash: false }), { botToken, now }).id, 42);
  assert.equal(validateTelegramInitData(signedInitData({ includeSignatureInHash: true }), { botToken, now }).id, 42);
  assert.throws(() => validateTelegramInitData(`${signedInitData({ includeSignatureInHash: false })}tampered`, { botToken, now }), /invalid/);
});
