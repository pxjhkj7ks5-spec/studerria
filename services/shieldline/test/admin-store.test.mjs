import assert from "node:assert/strict";
import test from "node:test";
import { newDb } from "pg-mem";
import { createAdminStore } from "../serverAdminStore.mjs";
import { createPostgresGameStore } from "../serverPostgresStore.mjs";

async function fixture() {
  const memory = newDb();
  const adapter = memory.adapters.createPg();
  const pool = new adapter.Pool();
  const legacyStore = { async getRun() { return null; }, async getRunEvents() { return null; }, async getRunSnapshots() { return null; } };
  const game = await createPostgresGameStore({ legacyStore, pool });
  const admin = await createAdminStore({ pool, ensureBaseSchema: false });
  await game.completeRegistration("guest-admin-test", { nickname: "Варта", nicknameNormalized: "варта", consentVersion: "v1" });
  await game.bindDevice("guest-admin-test", "device-hash", { platform: "web" });
  await game.attachIdentity("guest-admin-test", "telegram", "314", { username: "varta" });
  return { pool, game, admin };
}

test("admin sessions require the matching CSRF token and expire through revocation", async () => {
  const { pool, admin } = await fixture();
  const session = await admin.createSession("owner");
  assert.equal((await admin.verifySession(session.token, session.csrf)).label, "owner");
  assert.equal(await admin.verifySession(session.token, "wrong-csrf"), null);
  await admin.revokeSession(session.token);
  assert.equal(await admin.verifySession(session.token), null);
  await pool.end();
});

test("admin user controls are audited and anonymization removes identities and sessions", async () => {
  const { pool, admin } = await fixture();
  const actor = { source: "web", label: "owner" };
  const suspended = await admin.suspend(actor, "guest-admin-test", "Перевірка блокування");
  assert.equal(suspended.status, "suspended");
  assert.equal((await admin.listAudit()).at(0).action, "user.suspend");
  const active = await admin.activate(actor, "guest-admin-test", "Перевірка відновлення");
  assert.equal(active.status, "active");
  const anonymized = await admin.anonymize(actor, "guest-admin-test", "Запит користувача");
  assert.equal(anonymized.status, "anonymized");
  assert.equal(anonymized.telegram, null);
  assert.equal(anonymized.deviceCount, 0);
  assert.match(anonymized.nickname, /^deleted-/);
  await pool.end();
});

test("Telegram updates and confirmations are single-use and bound to the admin", async () => {
  const { pool, admin } = await fixture();
  assert.equal(await admin.beginBotUpdate(100), true);
  assert.equal(await admin.beginBotUpdate(100), false);
  await admin.finishBotUpdate(100);
  const token = await admin.createTelegramAction("42", "suspend", { actorId: "guest-admin-test" });
  assert.equal(await admin.consumeTelegramAction(token, "41"), null);
  assert.equal((await admin.consumeTelegramAction(token, "42")).action, "suspend");
  assert.equal(await admin.consumeTelegramAction(token, "42"), null);
  await pool.end();
});

test("broadcast preview respects active Telegram notification opt-in", async () => {
  const { pool, game, admin } = await fixture();
  assert.equal((await admin.previewBroadcast()).recipientCount, 0);
  await game.setNotificationPreference("guest-admin-test", "314", true);
  assert.equal((await admin.previewBroadcast()).recipientCount, 1);
  const queued = await admin.queueBroadcast({ source: "web", label: "owner" }, "Перевірка", "Тест");
  assert.equal(queued.recipientCount, 1);
  assert.equal(Number((await pool.query("SELECT count(*) AS count FROM shieldline_outbox WHERE type = 'admin.broadcast'")).rows[0].count), 1);
  await pool.end();
});
