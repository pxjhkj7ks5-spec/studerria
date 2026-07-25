import assert from "node:assert/strict";
import test from "node:test";
import { CAMPAIGN_REINFORCEMENT_ACTION, activeCampaignTutorialCue, campaignKillRewards, campaignMissionsPlan, campaignRouteTemplates, campaignTutorialComplete, campaignTutorialPlacementAction, campaignTutorialSteps, missionTargetCount, recordCampaignTutorialAction, settleCampaignTutorial } from "../src/data/campaignPlan";
import { accelerateFirstMissionSchedule, advanceCampaignMission, applyCampaignMissionOpening, buildCampaignSpawnEvents, campaignRedeployCost, createCampaignState, finalizeCampaignMission, generateCampaignRoute, recordCampaignKill, routeHasSelfIntersection, serviceCampaignBattery, unlockedCampaignMissionIndex } from "../src/game/campaignMeta";
import { campaignLaunchSectorIdsByAxis, pickCampaignLaunchSector } from "../src/game/campaignLaunchZones";
import { createDeterministicRandom } from "../src/game/deterministicRandom";
import { createScenarioState } from "../src/game/initialState";
import { createLaunchSectorState, sectorSupportsThreat } from "../src/game/launchSystem.mjs";
import { advanceSimulation, deployStoredBattery, moveBatteryToStorage, placeBattery, startAttackNow } from "../src/game/liveSimulation";
import { initialCities as gameCities } from "../src/data/mapData";

test("campaign catalog matches the five authored missions and target budgets", () => {
  assert.equal(campaignRouteTemplates.length, 36);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.title), ["Перший контакт", "Південний коридор", "Східна дуга", "Насичення", "Масована ніч"]);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.durationMinutes), [10, 35, 45, 50, 60]);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.grant), [42, 32, 48, 70, 100]);
  assert.ok(campaignMissionsPlan.every((mission) => !("rewardCap" in mission)));
  assert.deepEqual(campaignMissionsPlan.map(missionTargetCount), [23, 41, 58, 78, 103]);
  assert.equal(campaignMissionsPlan.slice(0, 3).some((mission) => mission.waves.some((wave) => wave.threatKind === "iskander")), false);
  assert.equal(campaignMissionsPlan.slice(3).every((mission) => mission.waves.some((wave) => wave.threatKind === "iskander")), true);
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

test("campaign economy credits every authored kill reward and preserves units without free ammo between missions", () => {
  let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game.resources.budget = 0;
  applyCampaignMissionOpening(game);
  assert.equal(game.resources.budget, 42);
  game = placeBattery(game, "radar", { lat: 49.2, lng: 29.4 }, () => .4);
  game = placeBattery(game, "mvg", { lat: 49.1, lng: 29.7 }, () => .6);
  assert.equal(game.resources.budget, 11);
  const mvg = game.batteries.find((battery) => battery.kind === "mvg")!;
  mvg.currentAmmo = 1;
  mvg.health = 76;
  const originalPosition = { ...mvg.position };
  for (let index = 0; index < 60; index += 1) recordCampaignKill(game, "parodiya", 1);
  assert.equal(game.resources.budget, 71);
  assert.equal(game.campaign?.campaignWallet, 71);
  game.interceptions = 30;
  const result = finalizeCampaignMission(game)!;
  assert.equal(result.killReward, 60);
  assert.equal(result.bonusRewards, 29);
  assert.equal(result.walletAfterMission, 100);
  assert.equal(mvg.currentAmmo, 1);
  assert.equal(mvg.health, 76);
  assert.equal(mvg.experienceLevel, 1);
  assert.deepEqual(mvg.position, originalPosition);

  game = advanceCampaignMission(game);
  assert.equal(game.campaign?.missionIndex, 2);
  assert.equal(game.resources.budget, 132);
  assert.equal(game.batteries.find((battery) => battery.id === mvg.id)?.currentAmmo, 1);
  assert.ok(game.campaign?.unlockedSystems.includes("gepard"));
});

test("campaign redeployment always costs one million regardless of the air-defense system", () => {
  for (const kind of ["small-radar", "radar", "long-radar", "mvg", "boat", "manpads", "gepard", "buk", "ew", "drone-operators", "s300", "iris-t", "nasams", "patriot"] as const) {
    assert.equal(campaignRedeployCost(kind), 1);
  }

  let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  applyCampaignMissionOpening(game);
  game = placeBattery(game, "radar", { lat: 49.2, lng: 29.4 }, () => .5);
  const radar = game.batteries.find((battery) => battery.kind === "radar")!;
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
  assert.equal(recordCampaignTutorialAction(campaign, "open-units", 1_000), false);
  assert.equal(settleCampaignTutorial(campaign, 4_999), false);
  assert.equal(settleCampaignTutorial(campaign, 5_000), true);
  assert.equal(campaign.tutorialStep, 2);
  assert.equal(activeCampaignTutorialCue(campaign, 9_999), null);
  assert.equal(activeCampaignTutorialCue(campaign, 10_000)?.title, "Розгорніть дальній радар");

  let nowMs = 10_000;
  for (const step of campaignTutorialSteps.slice(2)) {
    assert.equal(recordCampaignTutorialAction(campaign, step.action, nowMs), true);
    nowMs += 5_000;
  }
  assert.equal(campaignTutorialComplete(campaign), true);
  assert.equal(activeCampaignTutorialCue(campaign, nowMs), null);
  assert.equal(campaignTutorialPlacementAction("long-radar", { lat: 50.2, lng: 30.3 }, gameCities), "place-long-radar-near-kyiv");
  assert.equal(campaignTutorialPlacementAction("mvg", { lat: 50.2, lng: 31.0 }, gameCities), "place-mvg-east-of-kyiv");
  assert.equal(campaignTutorialPlacementAction("mvg", { lat: 50.2, lng: 29.8 }, gameCities), null);
  assert.deepEqual(
    ["parodiya", "gerbera", "geran2", "kh101", "kalibr", "iskander"].map((kind) => campaignKillRewards[kind as keyof typeof campaignKillRewards]),
    [1, 2, 2, 10, 10, 20],
  );
  assert.equal(buildCampaignSpawnEvents(1)[0].dueMs, 10_000);
});

test("first mission provides the tutorial radar and mobile fire group without spending the grant", () => {
  const random = createDeterministicRandom("campaign-s300-reinforcement");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  applyCampaignMissionOpening(game);
  assert.equal(game.campaign?.campaignWallet, 42);
  assert.ok(game.campaign?.unlockedSystems.includes("long-radar"));
  assert.equal(game.campaign?.unlockedSystems.includes("s300"), false);
  assert.deepEqual(game.storedBatteries.map((battery) => battery.kind).sort(), ["long-radar", "mvg"]);
  const radar = game.storedBatteries.find((battery) => battery.kind === "long-radar")!;
  game = deployStoredBattery(game, radar.id, { lat: 50.2, lng: 30.3 });
  assert.equal(game.campaign?.campaignWallet, 42);
  assert.equal(game.batteries.some((battery) => battery.kind === "long-radar"), true);
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
  game = advanceSimulation(game, 10_000, () => random.next());
  const threat = game.liveThreats[0];
  assert.ok(threat);
  assert.notEqual(threat.launchSectorId, threat.routeId);
  assert.equal(sectorSupportsThreat(game.launchSectors.find((sector) => sector.id === threat.launchSectorId)!, threat.kind), true);
  assert.deepEqual(threat.routeWaypoints?.[0], threat.origin);
  const activeSector = game.launchSectors.find((sector) => sector.id === threat.launchSectorId)!;
  assert.equal(activeSector.state, "launching");
  assert.deepEqual(activeSector.lastLaunchCoordinates, threat.origin);
});

test("clearing mission one pulls the next authored wave forward without changing its order", () => {
  let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  applyCampaignMissionOpening(game);
  game = startAttackNow(game, () => .5);
  game.campaign!.spawnCursor = 3;
  game.elapsedMs = game.cycleStartedAtMs + 20_000;
  const before = game.campaign!.spawnEvents.slice(3).map((event) => ({ id: event.id, dueMs: event.dueMs }));
  const shiftMs = accelerateFirstMissionSchedule(game);
  const after = game.campaign!.spawnEvents.slice(3);
  assert.ok(shiftMs > 0);
  assert.equal(after[0].dueMs, 28_000);
  assert.deepEqual(after.map((event) => event.id), before.map((event) => event.id));
  assert.deepEqual(after.slice(1).map((event, index) => event.dueMs - after[index].dueMs), before.slice(1).map((event, index) => event.dueMs - before[index].dueMs));
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
  game = advanceSimulation(game, 180_000, () => random.next());
  assert.equal(game.liveThreats.some((threat) => threat.id === cruiseId), false);
  assert.equal(game.campaign?.spawnCursor, 1);
  assert.equal(game.campaign?.intermission, true);
});

test("campaign kill earnings have no mission or wallet ceiling", () => {
  const game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  applyCampaignMissionOpening(game);
  for (let index = 0; index < 10_000; index += 1) recordCampaignKill(game, "parodiya", 1);
  assert.equal(game.campaign.missionKillReward, 10_000);
  assert.equal(game.campaign.campaignWallet, 10_042);
  assert.equal(game.resources.budget, 10_042);
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
  game = advanceSimulation(game, 120_000, () => random.next());
  assert.equal(game.liveThreats.some((threat) => threat.id === cruise.id), false);
});

test("intermission repair and resupply spend the persistent campaign wallet", () => {
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
  const before = game.campaign!.campaignWallet;
  game = serviceCampaignBattery(game, battery.id, "repair");
  assert.equal(battery.health, 100);
  assert.ok(game.campaign!.campaignWallet < before);
  const afterRepair = game.campaign!.campaignWallet;
  game = serviceCampaignBattery(game, battery.id, "resupply", .5);
  assert.ok((battery.missionReserve as number) > 0);
  assert.ok(game.campaign!.campaignWallet < afterRepair);
  assert.equal(game.resources.budget, game.campaign!.campaignWallet);
});

test("the live campaign director resolves every authored target before opening intermission", () => {
  const random = createDeterministicRandom("campaign-live-e2e");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game.resources.budget = 0;
  game.cities = game.cities.map((city) => ({ ...city, importance: 0 }));
  applyCampaignMissionOpening(game);
  game = startAttackNow(game, () => random.next());
  for (let step = 0; step < 8 && !game.campaign?.intermission; step += 1) game = advanceSimulation(game, 180_000, () => random.next());
  assert.equal(game.campaign?.spawnCursor, 23);
  assert.equal(game.campaign?.intermission, true);
  assert.equal(game.campaign?.previousMissionResults.length, 1);
  assert.equal(game.campaign?.previousMissionResults[0].totalTargets, 23);
  assert.equal(game.liveThreats.length, 0);
});
