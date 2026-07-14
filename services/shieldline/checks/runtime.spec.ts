import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { defenseReadinessForMode, gameModeRuntimePolicies } from "../src/data/gameModes";
import { createDeterministicRandom } from "../src/game/deterministicRandom";
import { mapZoomInputProfile } from "../src/game/mapZoom";
import { advanceSimulation, deployStoredBattery, moveBatteryToStorage, placeBattery, startAttackNow, tickSimulation } from "../src/game/liveSimulation";
import { createScenarioState } from "../src/game/initialState";
import { createLaunchSectorState } from "../src/game/launchSystem.mjs";
import { campaignCycleCompleted, normalizePersistedGame, useGameStore } from "../src/store/useGameStore";
import type { GameState, LiveThreat } from "../src/types/game";

function testThreat(): LiveThreat {
  return {
    id: "test-threat",
    kind: "geran2",
    status: "inbound",
    origin: { lat: 49.2, lng: 29.4 },
    target: { lat: 49.2, lng: 30.4 },
    targetCityId: "kyiv",
    launchSectorId: "test-sector",
    launchSectorName: "Test sector",
    progress: 0,
    speed: 1 / 120_000,
    difficulty: 10,
    damage: 3,
    confidence: 95,
    saturation: 1,
    headingDeg: 90,
    revealed: true,
    trackQuality: 95,
    reward: 2,
  };
}

function combatState(): GameState {
  const game = createScenarioState(() => 0.5, "training", "first-night");
  return { ...game, cyclePhase: "attack", cycleDurationMs: 999_999, liveThreats: [testThreat()] };
}

test("coverage circles and occupied polygons use Leaflet's shared SVG renderer", async () => {
  const source = await readFile(new URL("../src/components/TacticalMap.tsx", import.meta.url), "utf8");
  const coverageStart = source.indexOf("{visibleCoverageBatteries.map");
  const coverageEnd = source.indexOf("{visibleRoutes.map", coverageStart);
  const coverageLayer = source.slice(coverageStart, coverageEnd);

  assert.ok(coverageStart >= 0 && coverageEnd > coverageStart);
  assert.match(coverageLayer, /radius=\{unit\.outerRangeKm \* 1000\}/);
  assert.doesNotMatch(coverageLayer, /renderer=/);
  assert.doesNotMatch(source, /preferCanvas/);
  assert.doesNotMatch(source, /L\.svg\(\{ padding: 0\.6 \}\)/);
});

test("desktop wheel zoom is responsive while touch zoom keeps its existing profile", () => {
  assert.deepEqual(mapZoomInputProfile(true), { zoomDelta: 0.35, wheelPxPerZoomLevel: 70, wheelDebounceTime: 18 });
  assert.deepEqual(mapZoomInputProfile(false), { zoomDelta: 0.5, wheelPxPerZoomLevel: 160, wheelDebounceTime: 35 });
});

test("map panning defers React culling and tile updates until movement settles", async () => {
  const source = await readFile(new URL("../src/components/TacticalMap.tsx", import.meta.url), "utf8");
  const trackerStart = source.indexOf("function MapViewportTracker");
  const trackerEnd = source.indexOf("interface MovingObjectsLayerProps", trackerStart);
  const tracker = source.slice(trackerStart, trackerEnd);

  assert.ok(trackerStart >= 0 && trackerEnd > trackerStart);
  assert.doesNotMatch(tracker, /\bmove\(\)\s*\{/);
  assert.match(tracker, /moveend\(\)\s*\{\s*scheduleViewportFrame\(\)/);
  assert.match(source, /keepBuffer=\{4\}[\s\S]*?updateWhenIdle[\s\S]*?updateWhenZooming/);
  assert.doesNotMatch(source, /updateWhenIdle=\{false\}/);
});

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

test("combat modes auto-start only after radar and kinetic air defense are deployed", () => {
  const automaticModes = ["campaign", "rapid-response", "ranked-challenge", "co-op-command", "training"] as const;
  assert.ok(automaticModes.every((mode) => gameModeRuntimePolicies[mode].start === "auto-checklist"));

  const store = useGameStore.getState();
  store.launchTacticalMode("campaign");
  useGameStore.getState().beginPlacement("radar");
  useGameStore.getState().placeSelectedBattery({ lat: 49.2, lng: 29.4 });
  assert.equal(useGameStore.getState().operationPhase, "planning");
  useGameStore.getState().beginPlacement("buk");
  useGameStore.getState().placeSelectedBattery({ lat: 49.1, lng: 29.7 });
  assert.equal(useGameStore.getState().operationPhase, "countdown");
  assert.equal(useGameStore.getState().countdownRemainingMs, 5_000);
});

test("the deterministic cursor reproduces the same random sequence", () => {
  const left = createDeterministicRandom("golden-seed");
  const right = createDeterministicRandom("golden-seed");
  assert.deepEqual(Array.from({ length: 32 }, () => left.next()), Array.from({ length: 32 }, () => right.next()));
  assert.equal(left.cursor(), 32);
});

test("persisted operations reconcile stale launch data with the current catalog", () => {
  const currentSectors = createLaunchSectorState();
  const game = createScenarioState(() => 0.5, "training", "first-night");
  game.launchSectors = [
    { ...currentSectors[0], threats: ["kh101"] },
    { ...currentSectors[0], id: "legacy-sector", name: "Legacy sector" },
  ];
  game.liveThreats = [{ ...testThreat(), progress: 1 }];
  delete (game as Partial<GameState>).storedBatteries;

  const normalized = normalizePersistedGame(game);
  assert.ok(normalized);
  assert.deepEqual(normalized.launchSectors.map((sector) => sector.id), currentSectors.map((sector) => sector.id));
  assert.deepEqual(normalized.launchSectors[0].threats, currentSectors[0].threats);
  assert.equal(normalized.launchSectors.some((sector) => sector.id === "legacy-sector"), false);
  assert.equal(normalized.liveThreats.length, 0);
  assert.deepEqual(normalized.storedBatteries, []);
});

test("a battery keeps its condition and costs nothing when redeployed from storage", () => {
  let game = createScenarioState(() => 0.5, "training", "first-night");
  game = placeBattery(game, "mvg", { lat: 49.2, lng: 29.4 }, () => 0.5);
  const purchased = game.batteries[0];
  purchased.currentAmmo = 2;
  purchased.readiness = 73;
  const budgetAfterPurchase = game.resources.budget;

  game = moveBatteryToStorage(game, purchased.id);
  assert.equal(game.batteries.length, 0);
  assert.equal(game.storedBatteries.length, 1);
  assert.equal(game.resources.budget, budgetAfterPurchase);

  game = deployStoredBattery(game, purchased.id, { lat: 48.7, lng: 29.7 });
  assert.equal(game.storedBatteries.length, 0);
  assert.equal(game.batteries.length, 1);
  assert.equal(game.batteries[0].id, purchased.id);
  assert.equal(game.batteries[0].currentAmmo, 2);
  assert.equal(game.batteries[0].readiness, 73);
  assert.equal(game.resources.budget, budgetAfterPurchase);
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
  const launchedSector = game.launchSectors.find((sector) => sector.lastLaunchCoordinates);
  assert.ok(launchedSector);
  const launchedThreat = game.liveThreats.find((threat) => threat.launchSectorId === launchedSector.id);
  const pendingLaunch = game.pendingLaunches.find((launch) => launch.sectorId === launchedSector.id);
  assert.deepEqual(launchedSector.lastLaunchCoordinates, launchedThreat?.origin || pendingLaunch?.origin);
});

test("radars and absent defenses never create mystery interceptions", () => {
  const noDefense = tickSimulation(combatState(), 100, () => 0.999);
  assert.equal(noDefense.interceptorShots.length, 0);
  assert.equal(noDefense.interceptions, 0);

  let radarOnly = combatState();
  radarOnly = placeBattery(radarOnly, "radar", { lat: 49.2, lng: 29.4 }, () => 0.5);
  radarOnly = tickSimulation(radarOnly, 100, () => 0.999);
  assert.equal(radarOnly.interceptorShots.length, 0);
  assert.equal(radarOnly.interceptions, 0);
});

test("only an in-range real battery launches and resolves an interceptor", () => {
  let outOfRange = combatState();
  outOfRange = placeBattery(outOfRange, "mvg", { lat: 49.2, lng: 29.4 }, () => 0.5);
  outOfRange.batteries[0].position = { lat: 45, lng: 22 };
  outOfRange = tickSimulation(outOfRange, 100, () => 0.999);
  assert.equal(outOfRange.interceptorShots.length, 0);

  let game = combatState();
  game = placeBattery(game, "radar", { lat: 49.25, lng: 29.45 }, () => 0.5);
  game = placeBattery(game, "mvg", { lat: 49.2, lng: 29.4 }, () => 0.5);
  const battery = game.batteries[1];
  const ammoBefore = battery.currentAmmo;
  let cursor = 0;
  game = tickSimulation(game, 100, () => cursor++ === 0 ? 0.999 : 0);
  assert.equal(game.interceptorShots.length, 1);
  assert.equal(game.interceptorShots[0].batteryId, battery.id);
  assert.deepEqual(game.interceptorShots[0].from, battery.position);
  assert.ok(typeof ammoBefore === "number" && typeof game.batteries[1].currentAmmo === "number" && game.batteries[1].currentAmmo < ammoBefore);
  game = tickSimulation(game, 1_000, () => 0.999);
  assert.equal(game.interceptions, 1);
  assert.equal(game.liveThreats.some((threat) => threat.id === "test-threat"), false);
});

test("campaign completes after its first live attack cycle", () => {
  const previous = combatState();
  const next = {
    ...previous,
    cyclePhase: "planning" as const,
    afterActionReports: [{ id: "report-1" }, ...previous.afterActionReports] as GameState["afterActionReports"],
  };
  assert.equal(campaignCycleCompleted(previous, next), true);
});
