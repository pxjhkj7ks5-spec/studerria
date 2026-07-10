import assert from "node:assert/strict";
import test from "node:test";
import { defenseReadinessForMode, gameModeRuntimePolicies } from "../src/data/gameModes";
import { createDeterministicRandom } from "../src/game/deterministicRandom";
import { advanceSimulation, placeBattery, startAttackNow } from "../src/game/liveSimulation";
import { createScenarioState } from "../src/game/initialState";

test("the first six modes are live while Daily Defense is scheduled", () => {
  const liveModes = Object.entries(gameModeRuntimePolicies)
    .filter(([, policy]) => policy.execution === "live")
    .map(([id]) => id)
    .sort();
  assert.deepEqual(liveModes, ["campaign", "co-op-command", "ranked-challenge", "rapid-response", "sandbox", "training"]);
  assert.equal(gameModeRuntimePolicies["daily-defense"].execution, "daily-scheduled");
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
