import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { defenseReadinessForMode, gameModeRuntimePolicies } from "../src/data/gameModes";
import { getUnitDefinition } from "../src/data/units";
import { finalizeCampaignMission, createCampaignState } from "../src/game/campaignMeta";
import { createDeterministicRandom } from "../src/game/deterministicRandom";
import { mapZoomInputProfile } from "../src/game/mapZoom";
import { advanceSimulation, deployStoredBattery, engagementStyleForUnit, moveBatteryToStorage, placeBattery, startAttackNow, tickSimulation } from "../src/game/liveSimulation";
import { createScenarioState } from "../src/game/initialState";
import { createLaunchSectorState } from "../src/game/launchSystem.mjs";
import { campaignCycleCompleted, normalizePersistedGame, useGameStore } from "../src/store/useGameStore";
import { tacticalUnitStatus } from "../src/game/unitStatusDisplay";
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
    speedKph: 180,
    altitudeM: 120,
    difficulty: 10,
    damage: 3,
    confidence: 95,
    classification: "confirmed-type",
    displayLabel: "Тип підтверджено: Geran-2",
    saturation: 1,
    headingDeg: 90,
    revealed: true,
    trackQuality: 95,
    fireControlQuality: 95,
    speedModifier: 1,
    damageModifier: 1,
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
  assert.match(source, /state === "empty"[\s\S]*?color: "#ff625a"/);
  assert.match(source, /state === "maintenance"[\s\S]*?color: "#ffad42"/);
});

test("desktop wheel zoom uses predictable quarter-level steps while touch keeps continuous pinch zoom", () => {
  assert.deepEqual(mapZoomInputProfile(true), { zoomSnap: 0.25, zoomDelta: 0.25, wheelPxPerZoomLevel: 240, wheelDebounceTime: 40 });
  assert.deepEqual(mapZoomInputProfile(false), { zoomSnap: 0, zoomDelta: 0.5, wheelPxPerZoomLevel: 160, wheelDebounceTime: 35 });
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
  assert.match(source, /if \(mapMovingRef\.current\) return;/);
  assert.match(source, /setMapMotionRevision\(\(revision\) => revision \+ 1\)/);
  assert.match(source, /const CityExclusionCircle = memo/);
  assert.match(source, /<CityExclusionCircle[\s\S]*?reducedQuality=\{reducedQuality\}/);
  assert.doesNotMatch(source, /key=\{`city-exclusion-\$\{city\.id\}`\}[\s\S]{0,120}?center=\{/);
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
  useGameStore.getState().beginPlacement("mvg");
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
  const legacyThreat = { ...testThreat(), id: "legacy-live-threat", progress: 0.4 };
  delete (legacyThreat as Partial<LiveThreat>).speedKph;
  delete (legacyThreat as Partial<LiveThreat>).altitudeM;
  game.liveThreats = [{ ...testThreat(), progress: 1 }, legacyThreat];
  delete (game as Partial<GameState>).storedBatteries;

  const normalized = normalizePersistedGame(game);
  assert.ok(normalized);
  assert.deepEqual(normalized.launchSectors.map((sector) => sector.id), currentSectors.map((sector) => sector.id));
  assert.deepEqual(normalized.launchSectors[0].threats, currentSectors[0].threats);
  assert.equal(normalized.launchSectors.some((sector) => sector.id === "legacy-sector"), false);
  assert.equal(normalized.liveThreats.length, 1);
  assert.ok(normalized.liveThreats[0].speedKph > 0);
  assert.ok(normalized.liveThreats[0].altitudeM > 0);
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

test("campaign batteries refill a full magazine after the reload timer and expose the correct status", () => {
  let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game = placeBattery(game, "mvg", { lat: 49.2, lng: 29.4 }, () => .5);
  const battery = game.batteries[0];
  const unit = getUnitDefinition("mvg");
  battery.currentAmmo = 0;
  battery.status = "reloading";
  battery.reloadRemainingMs = 1_000;
  battery.readiness = 73;
  battery.fatigue = 60;

  game = tickSimulation(game, 500, () => .5);
  assert.equal(game.batteries[0].currentAmmo, 0);
  assert.equal(game.batteries[0].status, "reloading");
  assert.equal(game.batteries[0].reloadRemainingMs, 500);
  assert.equal(tacticalUnitStatus(unit, game.batteries[0]).label, "RELOADING");

  game = tickSimulation(game, 500, () => .5);
  assert.equal(game.batteries[0].currentAmmo, unit.ammoCapacity);
  assert.equal(game.batteries[0].reloadRemainingMs, 0);
  assert.equal(game.batteries[0].status, "strained");
  assert.equal(tacticalUnitStatus(unit, game.batteries[0]).label, "READY");
});

test("real impacts reduce live city resilience once while decoys do no damage", () => {
  let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game.cyclePhase = "attack";
  game.cycleDurationMs = 999_999;
  const cityBefore = { ...game.cities.find((city) => city.id === "kyiv")! };
  game.liveThreats = [{ ...testThreat(), progress: .999, speed: .01, damage: 9 }];
  game = tickSimulation(game, 100, () => .5);
  const cityAfter = game.cities.find((city) => city.id === "kyiv")!;
  assert.equal(game.campaign?.civilianResilience, 96);
  assert.ok(cityAfter.damage > cityBefore.damage);
  assert.ok(cityAfter.infrastructure < cityBefore.infrastructure);
  assert.ok(cityAfter.energy < cityBefore.energy);
  const resilienceBeforeAar = game.campaign!.civilianResilience;
  finalizeCampaignMission(game);
  assert.equal(game.campaign?.civilianResilience, resilienceBeforeAar);

  let decoyGame = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  decoyGame.campaign = createCampaignState();
  decoyGame.cyclePhase = "attack";
  decoyGame.cycleDurationMs = 999_999;
  const decoyCityBefore = { ...decoyGame.cities.find((city) => city.id === "kyiv")! };
  decoyGame.liveThreats = [{ ...testThreat(), kind: "parodiya", isFalseTrack: true, damage: 0, progress: .999, speed: .01 }];
  decoyGame = tickSimulation(decoyGame, 100, () => .5);
  const decoyCityAfter = decoyGame.cities.find((city) => city.id === "kyiv")!;
  assert.equal(decoyGame.campaign?.civilianResilience, 100);
  assert.equal(decoyCityAfter.damage, decoyCityBefore.damage);
  assert.equal(decoyCityAfter.infrastructure, decoyCityBefore.infrastructure);
  assert.equal(decoyCityAfter.energy, decoyCityBefore.energy);
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
  const matchingLaunch = game.launchSectors.some((sector) => sector.lastLaunchCoordinates && [
    ...game.liveThreats.filter((threat) => threat.launchSectorId === sector.id).map((threat) => threat.origin),
    ...game.pendingLaunches.filter((launch) => launch.sectorId === sector.id).map((launch) => launch.origin),
  ].some((origin) => origin.lat === sector.lastLaunchCoordinates?.lat && origin.lng === sector.lastLaunchCoordinates?.lng));
  assert.equal(matchingLaunch, true);
});

test("radars and absent defenses never create mystery interceptions", () => {
  const noDefense = tickSimulation(combatState(), 100, () => 0.999);
  assert.equal(noDefense.engagementEvents.length, 0);
  assert.equal(noDefense.interceptions, 0);

  let radarOnly = combatState();
  radarOnly = placeBattery(radarOnly, "radar", { lat: 49.2, lng: 29.4 }, () => 0.5);
  radarOnly = tickSimulation(radarOnly, 100, () => 0.999);
  assert.equal(radarOnly.engagementEvents.length, 0);
  assert.equal(radarOnly.interceptions, 0);
});

test("combat roles use distinct lightweight engagement visuals", () => {
  assert.equal(engagementStyleForUnit("patriot"), "missile");
  assert.equal(engagementStyleForUnit("gepard"), "gun");
  assert.equal(engagementStyleForUnit("ew"), "ew");
  assert.equal(engagementStyleForUnit("drone-operators"), "drone");
});

test("first radar contact creates a detection-only engagement event", () => {
  let game = combatState();
  game.elapsedMs = 900;
  game.liveThreats[0].revealed = false;
  game = placeBattery(game, "radar", { lat: 49.2, lng: 29.4 }, () => 0.5);
  game = tickSimulation(game, 100, () => 0.5);
  assert.equal(game.engagementEvents.length, 1);
  assert.equal(game.engagementEvents[0].style, "radar");
  assert.equal(game.engagementEvents[0].result, "detected");
  assert.equal(game.interceptions, 0);
});

test("only an in-range real battery launches and resolves an interceptor", () => {
  let outOfRange = combatState();
  outOfRange = placeBattery(outOfRange, "mvg", { lat: 49.2, lng: 29.4 }, () => 0.5);
  outOfRange.batteries[0].position = { lat: 45, lng: 22 };
  outOfRange = tickSimulation(outOfRange, 100, () => 0.999);
  assert.equal(outOfRange.engagementEvents.length, 0);

  let game = combatState();
  game = placeBattery(game, "radar", { lat: 49.25, lng: 29.45 }, () => 0.5);
  game = placeBattery(game, "mvg", { lat: 49.2, lng: 29.4 }, () => 0.5);
  const battery = game.batteries[1];
  const ammoBefore = battery.currentAmmo;
  let cursor = 0;
  game = tickSimulation(game, 100, () => cursor++ === 0 ? 0.999 : 0);
  assert.equal(game.engagementEvents.length, 1);
  assert.equal(game.engagementEvents[0].unitId, battery.id);
  assert.deepEqual(game.engagementEvents[0].startPosition, battery.position);
  assert.equal(game.engagementEvents[0].result, "success");
  assert.ok(typeof ammoBefore === "number" && typeof game.batteries[1].currentAmmo === "number" && game.batteries[1].currentAmmo < ammoBefore);
  game = tickSimulation(game, 1_000, () => 0.999);
  assert.equal(game.interceptions, 1);
  assert.equal(game.liveThreats.some((threat) => threat.id === "test-threat"), false);
});

test("interceptor prediction follows the assigned target route instead of a direct shortcut", () => {
  let game = combatState();
  game.liveThreats[0].target = { lat: 49.8, lng: 30 };
  game.liveThreats[0].routeWaypoints = [
    { ...game.liveThreats[0].origin },
    { lat: 49.2, lng: 30 },
    { ...game.liveThreats[0].target },
  ];
  game.liveThreats[0].progress = .08;
  game = placeBattery(game, "radar", { lat: 49.2, lng: 29.45 }, () => 0.5);
  game = placeBattery(game, "mvg", { lat: 49.2, lng: 29.5 }, () => 0.5);
  game = tickSimulation(game, 100, () => 0.999);

  const event = game.engagementEvents.find((item) => item.style === "gun");
  assert.ok(event);
  assert.ok(Math.abs(event.targetPredictedPosition.lat - 49.2) < .0001);
  assert.ok(event.targetPredictedPosition.lng > event.targetStartPosition.lng);
  assert.ok(event.targetPredictedPosition.lng < 30);
});

test("a failed engagement is animated and logged without removing the target", () => {
  let game = combatState();
  game = placeBattery(game, "radar", { lat: 49.25, lng: 29.45 }, () => 0.5);
  game = placeBattery(game, "mvg", { lat: 49.2, lng: 29.4 }, () => 0.5);
  game = tickSimulation(game, 100, () => 0.999);
  assert.equal(game.engagementEvents.length, 1);
  assert.equal(game.engagementEvents[0].result, "miss");
  assert.equal(game.liveThreats[0].status, "engaged");
  game = tickSimulation(game, 1_000, () => 0.999);
  assert.equal(game.interceptions, 0);
  assert.equal(game.liveThreats.some((threat) => threat.id === "test-threat"), true);
  assert.ok(game.log.some((entry) => entry.title === "Промах"));
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
