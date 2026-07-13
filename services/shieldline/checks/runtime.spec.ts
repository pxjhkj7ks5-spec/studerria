import assert from "node:assert/strict";
import test from "node:test";
import { defenseReadinessForMode, gameModeRuntimePolicies } from "../src/data/gameModes";
import { createDeterministicRandom } from "../src/game/deterministicRandom";
import { advanceSimulation, placeBattery, startAttackNow } from "../src/game/liveSimulation";
import { createScenarioState } from "../src/game/initialState";
import { campaignMissions } from "../src/data/missions";
import { projectCampaignRun } from "../src/game/campaignProjection";
import { runDeterministicMission } from "../src/game/deterministicMission";

test("the first six modes are live while Daily Defense is scheduled", () => {
  const liveModes = Object.entries(gameModeRuntimePolicies)
    .filter(([, policy]) => policy.execution === "live")
    .map(([id]) => id)
    .sort();
  assert.deepEqual(liveModes, ["campaign", "co-op-command", "ranked-challenge", "rapid-response", "sandbox", "training"]);
  assert.equal(gameModeRuntimePolicies["daily-defense"].execution, "daily-scheduled");
  assert.ok(Object.values(gameModeRuntimePolicies).every((policy) => policy.defaultSpeed === 1));
});

test("combat readiness requires a radar and a kinetic asset", () => {
  assert.equal(defenseReadinessForMode("campaign", []).ready, false);
  assert.equal(defenseReadinessForMode("campaign", ["radar"]).ready, false);
  assert.equal(defenseReadinessForMode("campaign", ["radar", "ew"]).ready, false);
  assert.equal(defenseReadinessForMode("campaign", ["radar", "buk"]).ready, true);
  assert.equal(defenseReadinessForMode("sandbox", []).ready, true);
});

test("the deterministic cursor reproduces the same random sequence", () => {
  const left = createDeterministicRandom("golden-seed");
  const right = createDeterministicRandom("golden-seed");
  assert.deepEqual(Array.from({ length: 32 }, () => left.next()), Array.from({ length: 32 }, () => right.next()));
  assert.equal(left.cursor(), 32);
});

test("a started live operation advances launch sectors and creates threats", () => {
  const random = createDeterministicRandom("launcher-regression");
  let game = createScenarioState(() => random.next(), "training", "first-night");
  game.liveThreats = [];
  game = placeBattery(game, "radar", { lat: 49.2, lng: 29.4 }, () => random.next());
  game = placeBattery(game, "buk", { lat: 49.1, lng: 29.7 }, () => random.next());
  assert.equal(game.batteries.length, 2);
  game = startAttackNow(game, () => random.next());
  game = advanceSimulation(game, 60_000, () => random.next());
  assert.equal(game.cyclePhase, "attack");
  assert.ok(game.liveThreats.length > 0 || game.impacts > 0 || game.interceptions > 0);
  assert.ok(game.log.some((entry) => entry.title === "Track Warning" || entry.title === "Missile Launch"));
});

test("campaign tactical projection follows the authoritative event timeline", () => {
  const run = runDeterministicMission(campaignMissions[0], "projection-golden", {
    assetCount: 2,
    radarCount: 1,
    kineticCount: 1,
    averageReadiness: 90,
    assets: [
      { kind: "radar", cityId: "kyiv", readiness: 90 },
      { kind: "buk", cityId: "kyiv", readiness: 90 },
    ],
  });
  const beforeLaunch = projectCampaignRun(run, 1_000)!;
  assert.equal(beforeLaunch.liveThreats.length, 0);
  const launched = run.events.find((event) => event.type === "threat.launched")!;
  const detected = run.events.find((event) => event.waveId === launched.waveId && event.type === "track.detected")!;
  const inFlight = projectCampaignRun(run, detected.occurredAtMs + 1_000)!;
  assert.ok(inFlight.launchSectors.some((sector) => sector.state === "cooldown"));
  assert.ok(inFlight.liveThreats.some((threat) => threat.revealed));
  const projectedThreat = inFlight.liveThreats.find((threat) => threat.id === `${launched.waveId}-track`)!;
  assert.ok(projectedThreat.progress > 0.2 && projectedThreat.progress < 0.4);
  assert.ok(Number(launched.payload.flightDurationMs) >= 20_000);
  const projectedSector = inFlight.launchSectors.find((sector) => sector.id === `campaign-launch-${launched.waveId}`)!;
  assert.ok(projectedSector);
  assert.deepEqual(
    { lat: projectedSector.lat, lng: projectedSector.lng },
    { lat: Number(launched.payload.originLat), lng: Number(launched.payload.originLng) },
  );
  assert.equal(projectedSector.radiusKm, 1);
  const complete = projectCampaignRun(run, run.events.at(-1)!.occurredAtMs)!;
  assert.ok(complete.launchSectors.length > 0);
  assert.ok(complete.launchSectors.every((sector) => sector.state === "cooldown"));
  assert.equal(complete.interceptions, run.interceptions);
  assert.equal(complete.impacts, run.impacts);
});
