import assert from "node:assert/strict";
import test from "node:test";
import { newDb } from "pg-mem";
import { createPostgresGameStore } from "../serverPostgresStore.mjs";

test("PostgreSQL adapter persists campaign runs, events, snapshots and progress", async () => {
  const memory = newDb();
  const adapter = memory.adapters.createPg();
  const pool = new adapter.Pool();
  const legacyStore = {
    async runMission() { throw new Error("Campaign must not dual-write through the JSON adapter."); },
    async getRun() { return null; },
    async getRunEvents() { return null; },
    async getRunSnapshots() { return null; },
    async campaignState() { return null; },
  };
  const store = await createPostgresGameStore({ legacyStore, pool });
  const run = await store.runMission("postgres-golden", "tg-42", { assetCount: 2, radarCount: 1, kineticCount: 1, averageReadiness: 90, assets: [{ id: "radar-1", kind: "radar", cityId: "kyiv", readiness: 90 }, { id: "mvg-1", kind: "mvg", cityId: "kyiv", readiness: 90 }] }, "first-contact", "campaign");
  assert.equal((await store.getRun(run.id)).id, run.id);
  assert.equal((await store.getRunEvents(run.id, 0)).length, run.events.length);
  assert.equal((await store.getRunSnapshots(run.id)).length, run.snapshots.length);
  const progress = await store.campaignState("tg-42");
  assert.equal(progress.lastRunId, run.id);
  assert.equal(progress.currentMissionId, "southern-corridor");
  assert.equal(progress.missions.length, 5);
  assert.equal(progress.missions[0].status, "completed");
  assert.equal(progress.missions[1].status, "active");
  assert.equal(Number((await pool.query("SELECT count(*) AS count FROM shieldline_cities")).rows[0].count), 1);
  assert.equal(Number((await pool.query("SELECT count(*) AS count FROM shieldline_assets")).rows[0].count), 2);
  await pool.end();
});

test("PostgreSQL auth adapter enforces identity and one-time code ownership", async () => {
  const memory = newDb();
  const adapter = memory.adapters.createPg();
  const pool = new adapter.Pool();
  const legacyStore = { async getRun() { return null; }, async getRunEvents() { return null; }, async getRunSnapshots() { return null; } };
  const store = await createPostgresGameStore({ legacyStore, pool });
  await store.completeRegistration("guest-auth", { nickname: "Варта", nicknameNormalized: "варта", consentVersion: "v1" });
  assert.equal(await store.nicknameAvailable("варта", "guest-other"), false);
  const parallel = await Promise.allSettled([
    store.completeRegistration("guest-parallel-a", { nickname: "Обрій", nicknameNormalized: "обрій", consentVersion: "v1" }),
    store.completeRegistration("guest-parallel-b", { nickname: "ОБРІЙ", nicknameNormalized: "обрій", consentVersion: "v1" }),
  ]);
  assert.equal(parallel.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(parallel.filter((result) => result.status === "rejected").length, 1);
  await store.bindDevice("guest-auth", "device-hash", { platform: "pwa" });
  assert.deepEqual(await store.findDevice("device-hash"), { actorId: "guest-auth" });
  await store.attachIdentity("guest-auth", "telegram", "314", { username: "varta" });
  assert.equal((await store.getAuthProfile("guest-auth")).telegram.id, "314");
  await store.createTransferCode("guest-auth", "code-hash", new Date(Date.now() + 60_000));
  assert.deepEqual(await store.consumeTransferCode("code-hash"), { actorId: "guest-auth" });
  await assert.rejects(() => store.consumeTransferCode("code-hash"), /недійсний/);
  const firstProgress = await store.savePlayerProgress("guest-auth", 0, { game: { campaign: { missionIndex: 2 } } });
  assert.equal(firstProgress.revision, 1);
  assert.equal((await store.getPlayerProgress("guest-auth")).state.game.campaign.missionIndex, 2);
  const secondProgress = await store.savePlayerProgress("guest-auth", 1, { game: { campaign: { missionIndex: 3 } } });
  assert.equal(secondProgress.revision, 2);
  await assert.rejects(
    () => store.savePlayerProgress("guest-auth", 1, { game: { campaign: { missionIndex: 1 } } }),
    (error) => error.statusCode === 409 && error.latestPatch.accountProgress.revision === 2,
  );
  await pool.end();
});
