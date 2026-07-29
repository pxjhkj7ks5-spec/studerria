import assert from "node:assert/strict";
import test from "node:test";
import { CAMPAIGN_REINFORCEMENT_ACTION, activeCampaignTutorialCue, campaignKillRewards, campaignMissionsPlan, campaignRouteTemplates, campaignTutorialComplete, campaignTutorialPlacementAction, missionTargetCount, recordCampaignTutorialAction, settleCampaignTutorial } from "../src/data/campaignPlan";
import { accelerateCampaignSchedule, advanceCampaignDepot, advanceCampaignMission, applyCampaignMissionOpening, buildCampaignSpawnEvents, campaignAmmoDepotPositions, campaignRedeployCost, captureCampaignAttemptCheckpoint, createCampaignState, damageCampaignDepot, finalizeCampaignMission, generateCampaignRoute, recordCampaignDefeat, recordCampaignKill, restoreCampaignAttempt, routeHasSelfIntersection, serviceCampaignBattery, serviceCampaignDepot, unlockedCampaignMissionIndex } from "../src/game/campaignMeta";
import { campaignLaunchSectorIdsByAxis, pickCampaignLaunchSector } from "../src/game/campaignLaunchZones";
import { createDeterministicRandom } from "../src/game/deterministicRandom";
import { createScenarioState } from "../src/game/initialState";
import { createLaunchSectorState, sectorSupportsThreat } from "../src/game/launchSystem.mjs";
import { advanceSimulation, deployStoredBattery, moveBatteryToStorage, placeBattery, startAttackNow, tickSimulation } from "../src/game/liveSimulation";
import { flightDurationForDistance, flightDurationForSpeed, GAMEPLAY_FLIGHT_SPEED_SCALE, routeDistanceKm, THREAT_FLIGHT_PROFILES } from "../src/game/threatFlightModel.mjs";
import { getUnitDefinition } from "../src/data/units";
import type { GameState, LiveThreat, ThreatKind } from "../src/types/game";

function advanceInRuntimeChunks(game: GameState, durationMs: number, random: () => number) {
  let next = game;
  for (let remainingMs = durationMs; remainingMs > 0;) {
    const stepMs = Math.min(60_000, remainingMs);
    next = advanceSimulation(next, stepMs, random);
    remainingMs -= stepMs;
  }
  return next;
}

test("campaign catalog matches the five authored missions and target budgets", () => {
  assert.equal(campaignRouteTemplates.length, 36);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.title), ["Перший контакт", "Південний маневр", "Сліпа зона", "Розірване небо", "Масована ніч"]);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.durationMinutes), [10, 22, 28, 34, 42]);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.grant), [24, 16, 24, 32, 45]);
  assert.ok(campaignMissionsPlan.every((mission) => mission.attackRegionHint.length >= 60));
  assert.ok(campaignMissionsPlan.every((mission) => mission.briefingHighlights.length === 2));
  assert.match(campaignMissionsPlan[1].briefingHighlights[0], /радар середньої дальності/);
  assert.match(campaignMissionsPlan[4].briefingHighlights[0], /Patriot/);
  assert.ok(campaignMissionsPlan.every((mission) => !("rewardCap" in mission)));
  assert.deepEqual(campaignMissionsPlan.map(missionTargetCount), [23, 42, 59, 78, 103]);
  const maximumKillRewards = campaignMissionsPlan.map((mission) => mission.waves.reduce((sum, wave) => sum + wave.count * (campaignKillRewards[wave.threatKind] || 0), 0));
  assert.deepEqual(maximumKillRewards, [50, 112, 174, 234, 341]);
  assert.deepEqual(campaignMissionsPlan.map((mission, index) => mission.grant + maximumKillRewards[index] + (index === 0 ? 29 : 39)), [103, 167, 237, 305, 425]);
  assert.ok(campaignMissionsPlan.every((mission) => (mission.waves.at(-1)?.timeSeconds || 0) < mission.durationMinutes * 60));
  assert.equal(campaignMissionsPlan[0].waves.some((wave) => wave.threatKind === "iskander"), false);
  assert.equal(campaignMissionsPlan[1].waves.at(-1)?.threatKind, "iskander");
  assert.equal(campaignMissionsPlan.slice(1).every((mission) => mission.waves.some((wave) => wave.threatKind === "iskander")), true);
});

test("special threats are restricted to their authored campaign corridors", () => {
  const routesFor = (kind: "recon" | "jammer" | "low-signature-cruise") =>
    campaignRouteTemplates.filter((route) => route.allowedThreats.includes(kind)).map((route) => route.id);

  assert.deepEqual(routesFor("recon"), ["R01", "R04", "R07", "R10", "R21", "R29"]);
  assert.deepEqual(routesFor("jammer"), ["R20", "R24", "R25", "R35"]);
  assert.deepEqual(routesFor("low-signature-cruise"), ["R20", "R25", "R31", "R35"]);
});

test("campaign mission selection unlocks only the next sequential mission", () => {
  const campaign = createCampaignState();
  assert.equal(unlockedCampaignMissionIndex(campaign), 1);
  campaign.intermission = true;
  assert.equal(unlockedCampaignMissionIndex(campaign), 2);
  campaign.missionIndex = 4;
  assert.equal(unlockedCampaignMissionIndex(campaign), 5);
  campaign.missionIndex = 5;
  campaign.completed = true;
  assert.equal(unlockedCampaignMissionIndex(campaign), 5);
});

test("authored waves expand to deterministic individual spawn events with grouping metadata", () => {
  for (const mission of campaignMissionsPlan) {
    const events = buildCampaignSpawnEvents(mission.index);
    assert.equal(events.length, missionTargetCount(mission));
    assert.ok(events.every((event, index) => index === 0 || event.dueMs >= events[index - 1].dueMs));
    assert.ok(events.every((event) => campaignRouteTemplates.some((route) => route.id === event.routeId && route.allowedThreats.includes(event.threatKind))));
  }
  const merged = buildCampaignSpawnEvents(3).find((event) => event.mergeRouteId && event.routeId !== event.mergeRouteId);
  assert.ok(merged?.rallyRatio && merged.rallyRatio >= .35 && merged.rallyRatio <= .6);

  const firstMissionSplit = buildCampaignSpawnEvents(1).filter((event) => event.groupId === "m1-w1-g1");
  assert.deepEqual(firstMissionSplit.map((event) => event.routeId), ["R01", "R29"]);
  assert.equal(firstMissionSplit.every((event) => event.trailPosition === undefined), true);

  const missionTwoPair = buildCampaignSpawnEvents(2).filter((event) => event.groupId === "m2-w2-g1");
  assert.deepEqual(missionTwoPair.map((event) => event.routeId), ["R10", "R10"]);
  assert.deepEqual(missionTwoPair.map((event) => event.trailPosition), [0, 1]);
  assert.equal(missionTwoPair[1].dueMs - missionTwoPair[0].dueMs, 7_000);

  const finalTenTargetTrail = buildCampaignSpawnEvents(5).filter((event) => event.groupId === "m5-w15-g1");
  assert.equal(finalTenTargetTrail.length, 10);
  assert.equal(new Set(finalTenTargetTrail.map((event) => event.routeId)).size, 1);
  assert.equal(new Set(finalTenTargetTrail.map((event) => event.trailLength)).size, 1);
  assert.equal(finalTenTargetTrail[0].trailLength, 10);
  assert.deepEqual(finalTenTargetTrail.slice(1).map((event, index) => event.dueMs - finalTenTargetTrail[index].dueMs), Array(9).fill(4_000));
});

test("live trail targets reuse one route and retain launch spacing", () => {
  const random = createDeterministicRandom("campaign-live-trail");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState(2);
  const pair = buildCampaignSpawnEvents(2)
    .filter((event) => event.groupId === "m2-w2-g1")
    .map((event, index) => ({ ...event, dueMs: 1_000 + index * 7_000 }));
  game.campaign.spawnEvents = pair;
  applyCampaignMissionOpening(game);
  game = startAttackNow(game, () => random.next());
  game = advanceSimulation(game, 500, () => random.next());
  const warnedSector = game.launchSectors.find((sector) => sector.state === "warning");
  assert.ok(warnedSector?.lastLaunchCoordinates);
  game = advanceSimulation(game, 9_500, () => random.next());
  const livePair = game.liveThreats.filter((threat) => threat.campaignGroupId === "m2-w2-g1");
  assert.equal(livePair.length, 2);
  assert.equal(livePair[0].launchSectorId, warnedSector.id);
  assert.deepEqual(livePair[0].origin, warnedSector.lastLaunchCoordinates);
  assert.deepEqual(livePair[0].origin, livePair[1].origin);
  assert.equal(livePair[0].launchSectorId, livePair[1].launchSectorId);
  assert.deepEqual(livePair[0].routeWaypoints, livePair[1].routeWaypoints);
  assert.ok(livePair[0].progress > livePair[1].progress);
});

test("every campaign mission starts its next cleared wave without a long idle gate", () => {
  const expectedFirstDueMs = [8_000, 12_000, 14_000, 16_000, 18_000];
  for (const missionIndex of [1, 2, 3, 4, 5]) {
    let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
    game.campaign = createCampaignState(missionIndex);
    applyCampaignMissionOpening(game);
    game = startAttackNow(game, () => .5);
    assert.ok(accelerateCampaignSchedule(game) > 0);
    assert.equal(game.campaign?.spawnEvents[0].dueMs, expectedFirstDueMs[missionIndex - 1]);
  }
});

test("first contact is a concise mixed battle with a real Caspian cruise wave", () => {
  const events = buildCampaignSpawnEvents(1);
  const gaps = events.slice(1).map((event, index) => event.dueMs - events[index].dueMs);
  assert.equal(events.length, 23);
  assert.ok(Math.max(...gaps) <= 75_000);
  assert.equal(events.filter((event) => event.threatKind !== "parodiya").length, 19);
  assert.equal(events.at(-1)!.dueMs < 8 * 60_000, true);
  assert.deepEqual(events.find((event) => event.threatKind === "kh101"), {
    id: "m1-w6-t1",
    dueMs: 275_000,
    threatKind: "kh101",
    routeId: "R32",
    groupId: "m1-w6-g1",
    mergeBehavior: "independent",
    priority: "veryHigh",
    targetRegion: "Столичний кластер",
    mergeRouteId: undefined,
    rallyRatio: undefined,
    targetAsset: undefined,
  });
  for (const groupId of new Set(events.map((event) => event.groupId))) {
    const group = events.filter((event) => event.groupId === groupId);
    assert.ok(group.length >= 1 && group.length <= 4);
    assert.ok(new Set(group.map((event) => event.routeId)).size >= 1);
  }
});

test("seeded route generation curves drones and keeps ballistic tracks direct", () => {
  const droneEvent = buildCampaignSpawnEvents(3).find((event) => event.threatKind === "geran2")!;
  const leftRandom = createDeterministicRandom("route-seed");
  const rightRandom = createDeterministicRandom("route-seed");
  const left = generateCampaignRoute(droneEvent, () => leftRandom.next());
  const right = generateCampaignRoute(droneEvent, () => rightRandom.next());
  assert.deepEqual(left, right);
  assert.ok(left.length >= 4);
  assert.equal(routeHasSelfIntersection(left), false);

  const ballisticEvent = buildCampaignSpawnEvents(4).find((event) => event.threatKind === "iskander")!;
  const ballistic = generateCampaignRoute(ballisticEvent, () => .5);
  assert.equal(ballistic.length, 2);
  assert.equal(routeHasSelfIntersection(ballistic), false);

  const launchOrigin = { lat: 53.2, lng: 34.4 };
  const adapted = generateCampaignRoute(droneEvent, () => leftRandom.next(), launchOrigin);
  const adaptedTemplate = campaignRouteTemplates.find((route) => route.id === droneEvent.routeId)!;
  assert.deepEqual(adapted[0], launchOrigin);
  assert.deepEqual(adapted.at(-1), adaptedTemplate.baseWaypoints.at(-1));
});

test("campaign corridors select compatible animated launch zones", () => {
  const sectors = createLaunchSectorState();
  for (const event of buildCampaignSpawnEvents(1)) {
    const route = campaignRouteTemplates.find((item) => item.id === event.routeId)!;
    const sector = pickCampaignLaunchSector(sectors, route.launchSector, event.threatKind, () => .35);
    assert.ok(campaignLaunchSectorIdsByAxis[route.launchSector].includes(sector.id));
    assert.equal(sectorSupportsThreat(sector, event.threatKind), true);
  }
  for (const mission of campaignMissionsPlan) for (const event of buildCampaignSpawnEvents(mission.index)) {
    const route = campaignRouteTemplates.find((item) => item.id === event.routeId)!;
    const sector = pickCampaignLaunchSector(sectors, route.launchSector, event.threatKind, () => .65, route.preferredLaunchSectorIds);
    assert.ok(sectors.some((item) => item.id === sector.id));
    assert.equal(sectorSupportsThreat(sector, event.threatKind), true);
    if (route.preferredLaunchSectorIds?.length) assert.ok(route.preferredLaunchSectorIds.includes(sector.id));
  }
});

test("long-range and southern cruise presets stay connected to their authored corridors", () => {
  const sectors = createLaunchSectorState();
  for (const routeId of ["R31", "R32", "R33", "R34", "R35", "R36"]) {
    const route = campaignRouteTemplates.find((item) => item.id === routeId)!;
    const kind = route.allowedThreats[0];
    const sector = pickCampaignLaunchSector(sectors, route.launchSector, kind, () => .5, route.preferredLaunchSectorIds);
    const event = { ...buildCampaignSpawnEvents(kind === "kalibr" ? 2 : 1)[0], routeId, threatKind: kind };
    const generated = generateCampaignRoute(event, () => .5, { lat: sector.lat, lng: sector.lng });
    assert.ok(route.preferredLaunchSectorIds?.includes(sector.id));
    assert.deepEqual(generated[0], { lat: sector.lat, lng: sector.lng });
    assert.ok(Math.abs(generated.at(-1)!.lat - route.baseWaypoints.at(-1)!.lat) < 1e-9);
    assert.ok(Math.abs(generated.at(-1)!.lng - route.baseWaypoints.at(-1)!.lng) < 1e-9);
    assert.equal(routeHasSelfIntersection(generated), false);
  }
});

test("campaign economy credits every authored kill reward and starts each new mission with full magazines and ten depot rounds", () => {
  let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game.resources.budget = 0;
  applyCampaignMissionOpening(game);
  assert.equal(game.resources.budget, 24);
  game = placeBattery(game, "small-radar", { lat: 49.2, lng: 29.4 }, () => .4);
  game = placeBattery(game, "mvg", { lat: 49.1, lng: 29.7 }, () => .6);
  assert.equal(game.resources.budget, 6);
  const mvg = game.batteries.find((battery) => battery.kind === "mvg")!;
  mvg.currentAmmo = 1;
  mvg.health = 76;
  const originalPosition = { ...mvg.position };
  for (let index = 0; index < 60; index += 1) recordCampaignKill(game, "parodiya", 1);
  assert.equal(game.resources.budget, 66);
  assert.equal(game.campaign?.campaignWallet, 66);
  game.interceptions = 30;
  game.cycleStartedAtMs = 12_000;
  game.elapsedMs = 112_000;
  const result = finalizeCampaignMission(game)!;
  assert.equal(result.durationSeconds, 100);
  assert.equal(result.killReward, 60);
  assert.equal(result.bonusRewards, 29);
  assert.equal(result.walletAfterMission, 95);
  assert.equal(mvg.currentAmmo, 1);
  assert.equal(mvg.health, 76);
  assert.equal(mvg.experienceLevel, 1);
  assert.deepEqual(mvg.position, originalPosition);
  game.campaign!.depot.stock = 42;

  game = advanceCampaignMission(game);
  assert.equal(game.campaign?.missionIndex, 2);
  assert.equal(game.resources.budget, 111);
  assert.equal(game.batteries.find((battery) => battery.id === mvg.id)?.currentAmmo, getUnitDefinition("mvg").ammoCapacity);
  assert.equal(game.campaign?.depot.stock, 10);
  assert.ok(game.campaign?.unlockedSystems.includes("gepard"));
  const reloadedMvg = game.batteries.find((battery) => battery.id === mvg.id)!;
  reloadedMvg.currentAmmo = 2;
  game.campaign!.depot.stock = 14;
  applyCampaignMissionOpening(game);
  assert.equal(reloadedMvg.currentAmmo, 2);
  assert.equal(game.campaign?.depot.stock, 14);
});

test("campaign redeployment always costs one million regardless of the air-defense system", () => {
  for (const kind of ["small-radar", "radar", "long-radar", "mvg", "boat", "manpads", "gepard", "buk", "ew", "drone-operators", "s300", "iris-t", "nasams", "patriot"] as const) {
    assert.equal(campaignRedeployCost(kind), 1);
  }

  let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  applyCampaignMissionOpening(game);
  game = placeBattery(game, "small-radar", { lat: 49.2, lng: 29.4 }, () => .5);
  const radar = game.batteries.find((battery) => battery.kind === "small-radar")!;
  game = moveBatteryToStorage(game, radar.id);
  const walletBeforeRedeployment = game.campaign!.campaignWallet;
  game = deployStoredBattery(game, radar.id, { lat: 48.7, lng: 30.1 });
  assert.equal(game.campaign?.campaignWallet, walletBeforeRedeployment - 1);
  assert.equal(game.batteries.find((battery) => battery.id === radar.id)?.position.lat, 48.7);
});

test("campaign onboarding advances by action and keeps five seconds between prompts", () => {
  const campaign = createCampaignState();
  assert.equal(activeCampaignTutorialCue(campaign, 0)?.title, "Розвідка: атака на Київ");
  assert.equal(recordCampaignTutorialAction(campaign, "open-intel", 0), true);
  assert.equal(campaign.tutorialStep, 1);
  assert.equal(activeCampaignTutorialCue(campaign, 4_999), null);
  assert.equal(recordCampaignTutorialAction(campaign, "inspect-ammo-depot", 5_000), true);
  assert.equal(campaign.tutorialStep, 2);
  assert.equal(recordCampaignTutorialAction(campaign, "open-units", 10_000), true);
  assert.equal(recordCampaignTutorialAction(campaign, "place-long-radar-near-kyiv", 15_000), true);
  assert.equal(recordCampaignTutorialAction(campaign, "place-mvg-east-of-kyiv", 20_000), true);
  assert.equal(recordCampaignTutorialAction(campaign, "purchase-depot-mvg", 25_000), true);
  assert.equal(recordCampaignTutorialAction(campaign, "place-mvg-near-depot", 30_000), true);
  assert.equal(activeCampaignTutorialCue(campaign, 35_000)?.title, "Підтвердьте план оборони");
  assert.equal(recordCampaignTutorialAction(campaign, "open-planning", 35_000), true);
  assert.equal(campaignTutorialComplete(campaign), true);
  assert.equal(activeCampaignTutorialCue(campaign, 40_000), null);
  assert.equal(campaignTutorialPlacementAction("long-radar"), "place-long-radar-near-kyiv");
  assert.equal(campaignTutorialPlacementAction("mvg"), "place-mvg-east-of-kyiv");
  assert.equal(campaignTutorialPlacementAction("radar"), null);
  assert.deepEqual(
    ["parodiya", "gerbera", "geran2", "recon", "kh101", "kalibr", "jammer", "low-signature-cruise", "iskander"].map((kind) => campaignKillRewards[kind as keyof typeof campaignKillRewards]),
    [1, 2, 2, 4, 10, 10, 12, 14, 20],
  );
  assert.equal(buildCampaignSpawnEvents(1)[0].dueMs, 10_000);
});

test("first mission provides the tutorial radar and mobile fire group without spending the grant", () => {
  const random = createDeterministicRandom("campaign-s300-reinforcement");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  applyCampaignMissionOpening(game);
  assert.equal(game.campaign?.campaignWallet, 24);
  assert.ok(game.campaign?.unlockedSystems.includes("long-radar"));
  assert.equal(game.campaign?.unlockedSystems.includes("s300"), false);
  assert.deepEqual(game.storedBatteries.map((battery) => battery.kind).sort(), ["long-radar", "mvg"]);
  const radar = game.storedBatteries.find((battery) => battery.kind === "long-radar")!;
  game = deployStoredBattery(game, radar.id, { lat: 50.2, lng: 30.3 });
  assert.equal(game.campaign?.campaignWallet, 24);
  assert.equal(game.batteries.some((battery) => battery.kind === "long-radar"), true);
  assert.equal(game.log[0].soundCue, "placement.success");
});

test("live campaign launches from and animates a named geographic direction", () => {
  const random = createDeterministicRandom("campaign-live-launch-zone");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  applyCampaignMissionOpening(game);
  game = startAttackNow(game, () => random.next());
  game = advanceSimulation(game, 1_000, () => random.next());
  const warningSector = game.launchSectors.find((sector) => sector.state === "warning");
  assert.ok(warningSector);
  assert.ok(warningSector.lastLaunchCoordinates);
  assert.equal(game.liveThreats.length, 0);
  game = advanceSimulation(game, 20_000, () => random.next());
  const threat = game.liveThreats[0];
  assert.ok(threat);
  assert.notEqual(threat.launchSectorId, threat.routeId);
  assert.equal(sectorSupportsThreat(game.launchSectors.find((sector) => sector.id === threat.launchSectorId)!, threat.kind), true);
  assert.deepEqual(threat.routeWaypoints?.[0], threat.origin);
  assert.equal(Math.ceil(1 / threat.speed), flightDurationForDistance(threat.kind, threat.speedKph, routeDistanceKm(threat.routeWaypoints!)));
  const depotDecoy = game.liveThreats.find((item) => item.targetAsset === "ammo-depot");
  assert.ok(depotDecoy);
  assert.deepEqual(depotDecoy.routeWaypoints?.[0], depotDecoy.origin);
  const kyiv = game.cities.find((city) => city.id === "kyiv")!;
  assert.ok(routeDistanceKm([depotDecoy.origin, kyiv.coordinates]) > 150);
  const activeSector = game.launchSectors.find((sector) => sector.id === threat.launchSectorId)!;
  assert.equal(activeSector.state, "launching");
  assert.deepEqual(activeSector.lastLaunchCoordinates, threat.origin);
});

test("clearing campaign waves pulls the next authored wave forward without changing its order", () => {
  let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  applyCampaignMissionOpening(game);
  game = startAttackNow(game, () => .5);
  game.campaign!.spawnCursor = 3;
  game.elapsedMs = game.cycleStartedAtMs + 20_000;
  const before = game.campaign!.spawnEvents.slice(3).map((event) => ({ id: event.id, dueMs: event.dueMs }));
  const shiftMs = accelerateCampaignSchedule(game);
  const after = game.campaign!.spawnEvents.slice(3);
  assert.ok(shiftMs > 0);
  assert.equal(after[0].dueMs, 28_000);
  assert.deepEqual(after.map((event) => event.id), before.map((event) => event.id));
  assert.deepEqual(after.slice(1).map((event, index) => event.dueMs - after[index].dueMs), before.slice(1).map((event, index) => event.dueMs - before[index].dueMs));

  let secondMission = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  secondMission.campaign = createCampaignState(2);
  applyCampaignMissionOpening(secondMission);
  secondMission = startAttackNow(secondMission, () => .5);
  secondMission.elapsedMs = secondMission.cycleStartedAtMs + 20_000;
  assert.ok(accelerateCampaignSchedule(secondMission) > 0);
  assert.equal(secondMission.campaign!.spawnEvents[0].dueMs, 32_000);
});

test("S-300 reinforcement is paired with a real Caspian warning, flight, and resolution", () => {
  const random = createDeterministicRandom("campaign-caspian-lifecycle");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game.campaign.spawnEvents = [{
    id: "caspian-tutorial-wave",
    dueMs: 30_000,
    threatKind: "kh101",
    routeId: "R32",
    groupId: "caspian-tutorial-wave",
    mergeBehavior: "independent",
    priority: "veryHigh",
    targetRegion: "Столичний кластер",
  }];
  applyCampaignMissionOpening(game);
  game = startAttackNow(game, () => random.next());
  game = advanceSimulation(game, 1_000, () => random.next());
  const reinforcement = game.storedBatteries.find((battery) => battery.kind === "s300");
  assert.ok(reinforcement);
  assert.equal(reinforcement.lastAction, CAMPAIGN_REINFORCEMENT_ACTION);
  const walletBeforeDeployment = game.campaign!.campaignWallet;
  game = deployStoredBattery(game, reinforcement.id, { lat: 50.15, lng: 31.1 });
  assert.equal(game.campaign!.campaignWallet, walletBeforeDeployment);
  game = advanceSimulation(game, 14_000, () => random.next());
  assert.equal(game.launchSectors.find((sector) => sector.id === "long_range_air_b")?.state, "warning");
  game = advanceSimulation(game, 15_000, () => random.next());
  const cruise = game.liveThreats.find((threat) => threat.kind === "kh101");
  assert.ok(cruise);
  assert.equal(cruise.routeId, "R32");
  assert.equal(cruise.launchSectorId, "long_range_air_b");
  assert.equal(game.log.some((entry) => entry.eventType === "launch" && entry.locationLabel?.includes("Каспійський")), true);
  const cruiseId = cruise.id;
  game = advanceInRuntimeChunks(game, Math.ceil(1 / cruise.speed) + 10_000, () => random.next());
  assert.equal(game.liveThreats.some((threat) => threat.id === cruiseId), false);
  assert.equal(game.campaign?.spawnCursor, 1);
  assert.equal(game.campaign?.intermission, true);
});

test("mission two grants one stocked Patriot exactly ninety seconds before its accelerated ballistic finale", () => {
  const random = createDeterministicRandom("campaign-patriot-reinforcement");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState(2, 16, "campaign-patriot-reinforcement");
  game.campaign.depot.stock = 9;
  game.campaign.spawnEvents = [{
    id: "m2-ballistic-finale",
    dueMs: 120_000,
    threatKind: "iskander",
    routeId: "R27",
    groupId: "m2-ballistic-finale",
    mergeBehavior: "independent",
    priority: "critical",
    targetRegion: "Південний портовий кластер",
  }];
  applyCampaignMissionOpening(game);
  assert.equal(game.campaign.unlockedSystems.includes("patriot"), false);
  const mediumRadar = game.storedBatteries.find((battery) => battery.id === "campaign-m2-medium-radar");
  assert.ok(mediumRadar);
  assert.equal(mediumRadar.kind, "radar");
  assert.equal(mediumRadar.lastAction, CAMPAIGN_REINFORCEMENT_ACTION);
  game = startAttackNow(game, () => random.next());
  game = tickSimulation(game, 1_000, () => random.next());
  const patriot = game.storedBatteries.find((battery) => battery.id === "campaign-m2-patriot-reinforcement");
  assert.ok(patriot);
  assert.equal(game.campaign.spawnEvents[0].dueMs - (game.elapsedMs - game.cycleStartedAtMs), 90_000);
  assert.equal(patriot.kind, "patriot");
  assert.equal(patriot.currentAmmo, 2);
  assert.equal(patriot.missionReserve, 0);
  assert.equal(game.campaign.depot.stock, 10);
  game = advanceSimulation(game, 30_000, () => random.next());
  assert.equal([...game.batteries, ...game.storedBatteries].filter((battery) => battery.id === patriot.id).length, 1);
});

test("campaign kill earnings have no mission or wallet ceiling", () => {
  const game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  applyCampaignMissionOpening(game);
  for (let index = 0; index < 10_000; index += 1) recordCampaignKill(game, "parodiya", 1);
  assert.equal(game.campaign.missionKillReward, 10_000);
  assert.equal(game.campaign.campaignWallet, 10_024);
  assert.equal(game.resources.budget, 10_024);
});

test("fixed model speeds drive route-distance flight time instead of an authored arrival deadline", () => {
  assert.equal(GAMEPLAY_FLIGHT_SPEED_SCALE, 1.1);
  assert.equal(THREAT_FLIGHT_PROFILES.geran2.speedKph, 170);
  assert.equal(THREAT_FLIGHT_PROFILES.kh101.speedKph, 780);
  assert.equal(THREAT_FLIGHT_PROFILES.iskander.speedKph, 5_200);
  const shortGeran = flightDurationForDistance("geran2", 170, 340);
  const longGeran = flightDurationForDistance("geran2", 170, 680);
  assert.equal(shortGeran, 130_909);
  assert.equal(longGeran, shortGeran * 2);
  assert.equal(flightDurationForSpeed("kh101", 780), flightDurationForDistance("kh101", 780, THREAT_FLIGHT_PROFILES.kh101.representativeDistanceKm));
});

test("full campaign corridors keep one canonical speed without trimming their launch point", () => {
  const durationRanges = new Map<ThreatKind, { min: number; max: number; speeds: Set<number> }>();
  for (const mission of campaignMissionsPlan) {
    for (const wave of mission.waves) {
      for (const routeId of wave.routeIds) {
        const route = campaignRouteTemplates.find((item) => item.id === routeId)!;
        const speedKph = THREAT_FLIGHT_PROFILES[wave.threatKind].speedKph;
        const durationMs = flightDurationForDistance(wave.threatKind, speedKph, routeDistanceKm(route.baseWaypoints));
        const range = durationRanges.get(wave.threatKind) || { min: Infinity, max: 0, speeds: new Set<number>() };
        range.min = Math.min(range.min, durationMs);
        range.max = Math.max(range.max, durationMs);
        range.speeds.add(speedKph);
        durationRanges.set(wave.threatKind, range);
      }
    }
  }
  for (const [kind, range] of durationRanges) {
    assert.equal(range.speeds.size, 1, `${kind} must use one canonical speed`);
    if (kind === "iskander" || kind === "ballistic") {
      assert.ok(range.min >= 40_000 && range.max <= 85_000, `${kind} must stay inside its ballistic corridor window`);
    } else {
      assert.ok(range.min >= 80_000 && range.max <= 400_000, `${kind} must use its complete authored corridor`);
    }
  }
});

test("campaign cruise missiles require sensor acquisition and complete their authored route", () => {
  const random = createDeterministicRandom("campaign-cruise-route");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game.campaign.spawnEvents = [{
    id: "cruise-route-check",
    dueMs: 10_000,
    threatKind: "kh101",
    routeId: "R31",
    groupId: "cruise-route-check",
    mergeBehavior: "independent",
    priority: "veryHigh",
    targetRegion: "Південно-східний кластер",
  }];
  applyCampaignMissionOpening(game);
  game = startAttackNow(game, () => random.next());
  game = advanceSimulation(game, 15_000, () => random.next());
  const cruise = game.liveThreats.find((threat) => threat.kind === "kh101");
  assert.ok(cruise);
  assert.equal(cruise.routeId, "R31");
  assert.equal(cruise.launchSectorId, "long_range_air_a");
  game = advanceSimulation(game, 10_000, () => random.next());
  assert.equal(game.liveThreats.find((threat) => threat.id === cruise.id)?.revealed, false);
  game = advanceInRuntimeChunks(game, Math.ceil(1 / cruise.speed) + 10_000, () => random.next());
  assert.equal(game.liveThreats.some((threat) => threat.id === cruise.id), false);
});

test("intermission repair spends the wallet while manual mission-reserve resupply stays retired", () => {
  let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game.resources.budget = 0;
  applyCampaignMissionOpening(game);
  game = placeBattery(game, "mvg", { lat: 49.1, lng: 29.7 }, () => .5);
  const battery = game.batteries[0];
  battery.health = 50;
  battery.currentAmmo = 0;
  battery.missionReserve = 0;
  game.campaign!.intermission = true;
  game.campaign!.depot.stock = 10;
  const before = game.campaign!.campaignWallet;
  game = serviceCampaignBattery(game, battery.id, "repair");
  assert.equal(battery.health, 100);
  assert.ok(game.campaign!.campaignWallet < before);
  const afterRepair = game.campaign!.campaignWallet;
  game = serviceCampaignBattery(game, battery.id, "resupply", .5);
  assert.equal(battery.missionReserve, 0);
  assert.equal(game.campaign!.campaignWallet, afterRepair);
  assert.match(game.placementWarning || "", /автоматично/);
  assert.equal(game.resources.budget, game.campaign!.campaignWallet);
});

test("the live campaign director resolves every authored target before opening intermission", () => {
  const random = createDeterministicRandom("campaign-live-e2e");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game.resources.budget = 0;
  game.cities = game.cities.map((city) => ({ ...city, infrastructure: 100, damage: 0 }));
  applyCampaignMissionOpening(game);
  game.campaign!.spawnEvents = game.campaign!.spawnEvents.map((event) => ({ ...event, targetAsset: "ammo-depot" }));
  game = startAttackNow(game, () => random.next());
  for (let step = 0; step < 8 && !game.campaign?.intermission; step += 1) game = advanceSimulation(game, 180_000, () => random.next());
  assert.equal(game.campaign?.spawnCursor, 23);
  assert.equal(game.campaign?.intermission, true);
  assert.equal(game.campaign?.previousMissionResults.length, 1);
  assert.equal(game.campaign?.previousMissionResults[0].totalTargets, 23);
  assert.equal(game.liveThreats.length, 0);
});

test("the authored depot targets preserve every mission target budget", () => {
  const expectedIds = [
    ["m1-w1-t2", "m1-w2-t2"],
    ["m2-w3-t2", "m2-w5-t2", "m2-w11-t2"],
    ["m3-w2-t2", "m3-w4-t1", "m3-w10-t2", "m3-w14-t1"],
    ["m4-w4-t2", "m4-w10-t1", "m4-w10-t3", "m4-w13-t1"],
    ["m5-w6-t2", "m5-w6-t4", "m5-w9-t2", "m5-w13-t3", "m5-w13-t6", "m5-w13-t9", "m5-w14-t3", "m5-w18-t1"],
  ];
  for (const mission of campaignMissionsPlan) {
    const events = buildCampaignSpawnEvents(mission.index);
    assert.equal(events.length, missionTargetCount(mission));
    assert.deepEqual(events.filter((event) => event.targetAsset === "ammo-depot").map((event) => event.id), expectedIds[mission.index - 1]);
  }
});

test("campaign depot is seeded, uncapped, damageable and repaired only during active combat", () => {
  const positions = new Set(campaignAmmoDepotPositions.map((position) => `${position.lat}:${position.lng}`));
  const seededPositions = new Set(Array.from({ length: 32 }, (_, index) => {
    const depot = createCampaignState(1, 0, `depot-seed-${index}`).depot;
    assert.ok(positions.has(`${depot.position.lat}:${depot.position.lng}`));
    return `${depot.position.lat}:${depot.position.lng}`;
  }));
  assert.ok(seededPositions.size > 1);
  for (const position of campaignAmmoDepotPositions) {
    const placementGame = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
    const placed = placeBattery(placementGame, "mvg", { lat: position.lat + .03, lng: position.lng }, () => .5);
    assert.equal(placed.batteries.length, placementGame.batteries.length + 1, `depot at ${position.lat},${position.lng} must allow close defense`);
  }

  const game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState(1, 24, "depot-production");
  game.resources.budget = 24;
  assert.equal(game.campaign.depot.stock, 10);
  advanceCampaignDepot(game, 45_000, false);
  assert.equal(game.campaign.depot.stock, 12);
  advanceCampaignDepot(game, 45_000, false);
  assert.equal(game.campaign.depot.stock, 14);
  game.campaign.depot.health = 50;
  advanceCampaignDepot(game, 45_000, false);
  assert.equal(game.campaign.depot.stock, 15);
  game.campaign.depot.stock = 10_001;
  advanceCampaignDepot(game, 45_000, false);
  assert.equal(game.campaign.depot.stock, 10_002);

  game.campaign.depot.health = 10;
  const firstImpact = damageCampaignDepot(game, 10);
  assert.equal(firstImpact.damage, 12.5);
  assert.equal(game.campaign.depot.health, 0);
  assert.equal(game.campaign.depot.stock, 5_001);
  assert.equal(firstImpact.stockLost, 5_001);
  assert.equal(damageCampaignDepot(game, 50).stockLost, 0);

  serviceCampaignDepot(game);
  assert.equal(game.campaign.campaignWallet, 12);
  assert.equal(game.campaign.depot.repairRemainingMs, 120_000);
  advanceCampaignDepot(game, 60_000, false);
  assert.equal(game.campaign.depot.repairRemainingMs, 120_000);
  advanceCampaignDepot(game, 60_000, true);
  assert.equal(game.campaign.depot.repairRemainingMs, 60_000);
  advanceCampaignDepot(game, 60_000, true);
  assert.equal(game.campaign.depot.repairRemainingMs, 0);
  assert.equal(game.campaign.depot.health, 100);
});

test("retry restores the complete pre-attack checkpoint and adopts authored depot targets", () => {
  const game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState(1, 24, "retry-checkpoint");
  game.resources.budget = 24;
  game.cities = game.cities.map((city) => ({ ...city, infrastructure: 100, damage: 0 }));
  game.campaign.depot.stock = 7;
  game.campaign.spawnEvents = game.campaign.spawnEvents.map((event) => ({ ...event, targetAsset: undefined }));
  captureCampaignAttemptCheckpoint(game, 17);
  game.campaign.campaignWallet = 99;
  game.resources.budget = 99;
  game.campaign.depot.stock = 42;
  game.cities[0].infrastructure = 0;
  game.cities[0].damage = 100;
  recordCampaignDefeat(game, game.cities[0].id);

  const restored = restoreCampaignAttempt(game)!;
  assert.equal(restored.simulationRandomCursor, 17);
  assert.equal(restored.game.resources.budget, 24);
  assert.equal(restored.game.campaign?.campaignWallet, 24);
  assert.equal(restored.game.campaign?.depot.stock, 7);
  assert.ok(restored.game.cities.every((city) => city.infrastructure === 100 && city.damage === 0));
  assert.equal(restored.game.campaign?.lastAttemptResult, null);
  assert.equal(restored.game.campaign?.previousMissionResults.length, 0);
  assert.deepEqual(restored.game.campaign?.spawnEvents.filter((event) => event.targetAsset === "ammo-depot").map((event) => event.id), ["m1-w1-t2", "m1-w2-t2"]);
});

test("100 seeded engagements meet the S-300 cruise and Patriot ballistic acceptance floors", () => {
  function runTrial(kind: "kh101" | "iskander", unitKind: "s300" | "patriot", seed: string) {
    const random = createDeterministicRandom(seed);
    let game = createScenarioState(() => random.next(), "training", "first-night");
    game.resources.budget = 999;
    game = placeBattery(
      game,
      unitKind,
      unitKind === "s300" ? { lat: 50.45, lng: 30.8 } : { lat: 46.2, lng: 30.8 },
      () => random.next(),
    );
    game.campaign = createCampaignState(unitKind === "s300" ? 1 : 2, 0, seed);
    game.campaign.spawnEvents = [];
    game.campaign.spawnCursor = 0;
    game.cities = game.cities.map((city) => ({ ...city, infrastructure: 100, damage: 0 }));
    game.cyclePhase = "attack";
    game.cycleDurationMs = 999_999;
    const targetCityId = kind === "kh101" ? "kyiv" : "odesa";
    const target = game.cities.find((city) => city.id === targetCityId)!.coordinates;
    const speedKph = kind === "kh101" ? 800 : 5_200;
    const durationMs = flightDurationForSpeed(kind, speedKph);
    const subject: LiveThreat = {
      id: "acceptance-subject",
      kind,
      status: "inbound",
      origin: kind === "kh101" ? { lat: 50.45, lng: 32 } : { lat: 46.2, lng: 33.8 },
      target,
      targetCityId,
      launchSectorId: "acceptance-sector",
      launchSectorName: "Acceptance sector",
      progress: 0,
      speed: 1 / durationMs,
      speedKph,
      altitudeM: kind === "kh101" ? 100 : 30_000,
      difficulty: 10,
      damage: kind === "kh101" ? 34 : 50,
      confidence: 22,
      classification: "unknown",
      displayLabel: "Невідомий контакт",
      saturation: 1,
      headingDeg: 270,
      revealed: false,
      trackQuality: 0,
      fireControlQuality: 0,
      speedModifier: 1,
      damageModifier: 1,
      reward: kind === "kh101" ? 10 : 20,
    };
    game.liveThreats = [subject];
    let firedAtProgress: number | null = null;
    for (let elapsed = 0; elapsed < durationMs + 5_000 && game.liveThreats.some((threat) => threat.id === subject.id); elapsed += 1_000) {
      game = tickSimulation(game, 1_000, () => random.next());
      if (firedAtProgress === null && game.engagementEvents.some((event) => event.targetId === subject.id && event.style !== "radar")) {
        firedAtProgress = game.liveThreats.find((threat) => threat.id === subject.id)?.progress ?? 1;
      }
    }
    return { firedAtProgress, intercepted: game.interceptions > 0 };
  }

  let s300FiredInTime = 0;
  let s300Intercepted = 0;
  let patriotFiredInTime = 0;
  let patriotIntercepted = 0;
  for (let index = 0; index < 100; index += 1) {
    const s300 = runTrial("kh101", "s300", `s300-acceptance-${index}`);
    const patriot = runTrial("iskander", "patriot", `patriot-acceptance-${index}`);
    if (s300.firedAtProgress !== null && s300.firedAtProgress <= .9) s300FiredInTime += 1;
    if (s300.intercepted) s300Intercepted += 1;
    if (patriot.firedAtProgress !== null && patriot.firedAtProgress <= .85) patriotFiredInTime += 1;
    if (patriot.intercepted) patriotIntercepted += 1;
  }
  assert.ok(s300FiredInTime >= 90, `S-300 fired in time for ${s300FiredInTime}/100 seeds`);
  assert.ok(s300Intercepted >= 80, `S-300 intercepted ${s300Intercepted}/100 seeds`);
  assert.ok(patriotFiredInTime >= 90, `Patriot fired in time for ${patriotFiredInTime}/100 seeds`);
  assert.ok(patriotIntercepted >= 85, `Patriot intercepted ${patriotIntercepted}/100 seeds`);
});
