import assert from "node:assert/strict";
import test from "node:test";
import { performance } from "node:perf_hooks";
import { campaignMissions } from "../src/data/missions.ts";
import { projectCampaignRun } from "../src/game/campaignProjection.ts";
import { runDeterministicMission } from "../src/game/deterministicMission.ts";

test("campaign live projection stays below the two-second acceptance budget", () => {
  const run = runDeterministicMission(campaignMissions[0], "performance-golden", {
    assetCount: 8,
    radarCount: 2,
    kineticCount: 6,
    averageReadiness: 84,
    assets: [],
  });
  const end = run.events.at(-1).occurredAtMs;
  const started = performance.now();
  for (let index = 0; index < 5_000; index += 1) projectCampaignRun(run, (index / 4_999) * end);
  const elapsed = performance.now() - started;
  assert.ok(elapsed < 2_000, `5,000 live projections took ${elapsed.toFixed(1)}ms`);
});
