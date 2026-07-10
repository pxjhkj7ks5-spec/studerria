import assert from "node:assert/strict";
import test from "node:test";
import { newDb } from "pg-mem";
import { createPostgresGameStore } from "../serverPostgresStore.mjs";
import { simulateMission } from "../serverGame.mjs";

test("PostgreSQL adapter persists campaign runs, events, snapshots and progress", async () => {
  const memory = newDb();
  const adapter = memory.adapters.createPg();
  const pool = new adapter.Pool();
  const legacyStore = {
    async runMission(seed, _actorId, _plan, missionId) { return simulateMission(seed, "2026-07-10T00:00:00.000Z", 0.12, missionId); },
    async getRun() { return null; },
    async getRunEvents() { return null; },
    async getRunSnapshots() { return null; },
    async campaignState() { return null; },
  };
  const store = await createPostgresGameStore({ legacyStore, pool });
  const run = await store.runMission("postgres-golden", "tg-42", { assetCount: 2 }, "campaign-night-01", "campaign");
  assert.equal((await store.getRun(run.id)).id, run.id);
  assert.equal((await store.getRunEvents(run.id, 0)).length, run.events.length);
  assert.equal((await store.getRunSnapshots(run.id)).length, run.snapshots.length);
  const progress = await store.campaignState("tg-42");
  assert.equal(progress.lastRunId, run.id);
  assert.equal(progress.currentMissionId, "campaign-night-02");
  await pool.end();
});
