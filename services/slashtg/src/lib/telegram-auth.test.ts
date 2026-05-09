import assert from "node:assert/strict";
import test from "node:test";
import { findAllowedUserByTelegramId } from "./config";
import {
  signTelegramInitDataForTest,
  validateTelegramInitData,
} from "./telegram-auth";

const botToken = "123456:test-token";
const nowSeconds = 1_800_000_000;

function signedInitData(overrides: Record<string, string> = {}) {
  return signTelegramInitDataForTest(
    {
      auth_date: String(nowSeconds),
      query_id: "AAHdF6IQAAAAAN0XohDhrOrc",
      user: JSON.stringify({
        id: 42,
        first_name: "Slash",
        username: "slash_user",
      }),
      ...overrides,
    },
    botToken,
  );
}

test("validates signed Telegram init data", () => {
  const result = validateTelegramInitData(signedInitData(), {
    botToken,
    nowSeconds,
    maxAgeSeconds: 86400,
  });

  assert.equal(String(result.user.id), "42");
  assert.equal(result.user.first_name, "Slash");
  assert.equal(result.authDate, nowSeconds);
});

test("rejects tampered Telegram init data", () => {
  const tampered = signedInitData().replace("Slash", "Other");

  assert.throws(
    () =>
      validateTelegramInitData(tampered, {
        botToken,
        nowSeconds,
        maxAgeSeconds: 86400,
      }),
    /invalid_hash/,
  );
});

test("rejects expired Telegram init data", () => {
  assert.throws(
    () =>
      validateTelegramInitData(signedInitData({ auth_date: String(nowSeconds - 90_000) }), {
        botToken,
        nowSeconds,
        maxAgeSeconds: 86400,
      }),
    /expired_init_data/,
  );
});

test("rejects init data without user payload", () => {
  assert.throws(
    () =>
      validateTelegramInitData(signedInitData({ user: "" }), {
        botToken,
        nowSeconds,
        maxAgeSeconds: 86400,
      }),
    /missing_user/,
  );
});

test("maps only allowed Telegram IDs", () => {
  const env = {
    SLASHTG_USER_A_TELEGRAM_ID: "42",
    SLASHTG_USER_B_TELEGRAM_ID: "77",
    SLASHTG_USER_A_LABEL: "A",
    SLASHTG_USER_B_LABEL: "B",
  } as NodeJS.ProcessEnv;

  assert.equal(findAllowedUserByTelegramId("42", env)?.keyName, "userA");
  assert.equal(findAllowedUserByTelegramId("77", env)?.keyName, "userB");
  assert.equal(findAllowedUserByTelegramId("99", env), null);
});

test("dev mock ID is not implicitly allowed without allowlist match", () => {
  const env = {
    SLASHTG_USER_A_TELEGRAM_ID: "42",
    SLASHTG_USER_B_TELEGRAM_ID: "77",
    SLASHTG_DEV_TELEGRAM_USER_ID: "99",
  } as NodeJS.ProcessEnv;

  assert.equal(findAllowedUserByTelegramId(env.SLASHTG_DEV_TELEGRAM_USER_ID, env), null);
});
