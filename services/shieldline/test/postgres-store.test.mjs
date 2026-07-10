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
  const run = await store.runMission("postgres-golden", "tg-42", { assetCount: 2, radarCount: 1, kineticCount: 1, averageReadiness: 90, assets: [{ id: "radar-1", kind: "radar", cityId: "kyiv", readiness: 90 }, { id: "buk-1", kind: "buk", cityId: "kyiv", readiness: 90 }] }, "campaign-night-01", "campaign");
  assert.equal((await store.getRun(run.id)).id, run.id);
  assert.equal((await store.getRunEvents(run.id, 0)).length, run.events.length);
  assert.equal((await store.getRunSnapshots(run.id)).length, run.snapshots.length);
  const progress = await store.campaignState("tg-42");
  assert.equal(progress.lastRunId, run.id);
  assert.equal(progress.currentMissionId, "campaign-night-02");
  assert.equal(Number((await pool.query("SELECT count(*) AS count FROM shieldline_cities")).rows[0].count), 1);
  assert.equal(Number((await pool.query("SELECT count(*) AS count FROM shieldline_assets")).rows[0].count), 2);
  await pool.end();
});
