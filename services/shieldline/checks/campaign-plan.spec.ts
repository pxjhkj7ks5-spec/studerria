import assert from "node:assert/strict";
import test from "node:test";
import { activeCampaignTutorialCue, campaignKillRewards, campaignMissionsPlan, campaignRouteTemplates, missionTargetCount } from "../src/data/campaignPlan";
import { advanceCampaignMission, applyCampaignMissionOpening, buildCampaignSpawnEvents, campaignRedeployCost, createCampaignState, finalizeCampaignMission, generateCampaignRoute, recordCampaignKill, routeHasSelfIntersection, serviceCampaignBattery, unlockedCampaignMissionIndex } from "../src/game/campaignMeta";
import { campaignLaunchSectorIdsByAxis, pickCampaignLaunchSector } from "../src/game/campaignLaunchZones";
import { createDeterministicRandom } from "../src/game/deterministicRandom";
import { createScenarioState } from "../src/game/initialState";
import { createLaunchSectorState, sectorSupportsThreat } from "../src/game/launchSystem.mjs";
import { advanceSimulation, deployStoredBattery, moveBatteryToStorage, placeBattery, startAttackNow } from "../src/game/liveSimulation";

test("campaign catalog matches the five authored missions and target budgets", () => {
  assert.equal(campaignRouteTemplates.length, 36);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.title), ["Перший контакт", "Південний коридор", "Східна дуга", "Насичення", "Масована ніч"]);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.durationMinutes), [15, 35, 45, 50, 60]);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.grant), [38, 32, 48, 70, 100]);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.rewardCap), [52, 82, 130, 198, 283]);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.waves.reduce((sum, wave) => sum + wave.count * campaignKillRewards[wave.threatKind], 0)), campaignMissionsPlan.map((mission) => mission.rewardCap));
  assert.deepEqual(campaignMissionsPlan.map(missionTargetCount), [29, 41, 58, 78, 103]);
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

test("first contact keeps pressure active without doubling damaging targets", () => {
  const events = buildCampaignSpawnEvents(1);
  const gaps = events.slice(1).map((event, index) => event.dueMs - events[index].dueMs);
  assert.equal(events.length, 29);
  assert.ok(Math.max(...gaps) <= 55_000);
  assert.equal(events.filter((event) => event.threatKind !== "parodiya").length, 15);
  for (const groupId of new Set(events.map((event) => event.groupId))) {
    const group = events.filter((event) => event.groupId === groupId);
    if (group[0].threatKind === "kh101") assert.equal(group.length, 1);
    else {
      assert.equal(group.length, 2);
      assert.equal(new Set(group.map((event) => event.routeId)).size, 2);
    }
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
  assert.equal(game.resources.budget, 38);
  game = placeBattery(game, "radar", { lat: 49.2, lng: 29.4 }, () => .4);
  game = placeBattery(game, "mvg", { lat: 49.1, lng: 29.7 }, () => .6);
  assert.equal(game.resources.budget, 7);
  const mvg = game.batteries.find((battery) => battery.kind === "mvg")!;
  mvg.currentAmmo = 1;
  mvg.health = 76;
  const originalPosition = { ...mvg.position };
  for (let index = 0; index < 60; index += 1) recordCampaignKill(game, "parodiya", 1);
  assert.equal(game.resources.budget, 67);
  assert.equal(game.campaign?.campaignWallet, 67);
  game.interceptions = 29;
  const result = finalizeCampaignMission(game)!;
  assert.equal(result.killReward, 60);
  assert.equal(result.bonusRewards, 25);
  assert.equal(result.walletAfterMission, 92);
  assert.equal(mvg.currentAmmo, 1);
  assert.equal(mvg.health, 76);
  assert.equal(mvg.experienceLevel, 1);
  assert.deepEqual(mvg.position, originalPosition);

  game = advanceCampaignMission(game);
  assert.equal(game.campaign?.missionIndex, 2);
  assert.equal(game.resources.budget, 124);
  assert.equal(game.batteries.find((battery) => battery.id === mvg.id)?.currentAmmo, 1);
  assert.ok(game.campaign?.unlockedSystems.includes("gepard"));
});

test("campaign redeployment always costs one million regardless of the air-defense system", () => {
  for (const kind of ["mvg", "boat", "manpads", "gepard", "buk", "ew", "drone-operators", "radar", "s300", "iris-t", "nasams", "patriot"] as const) {
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

test("campaign onboarding cues expire before the first launch", () => {
  assert.equal(activeCampaignTutorialCue(5)?.title, "Відкрийте «План»");
  assert.equal(activeCampaignTutorialCue(5, ["planning"]), null);
  assert.equal(activeCampaignTutorialCue(13), null);
  assert.equal(activeCampaignTutorialCue(510)?.title, "Підкріплення прибуло");
  assert.equal(activeCampaignTutorialCue(570), null);
  assert.equal(activeCampaignTutorialCue(810), null);
  assert.deepEqual(
    ["parodiya", "gerbera", "geran2", "kh101", "kalibr", "iskander"].map((kind) => campaignKillRewards[kind as keyof typeof campaignKillRewards]),
    [1, 2, 2, 10, 10, 20],
  );
  assert.equal(buildCampaignSpawnEvents(1)[0].dueMs, 45_000);
});

test("first mission grants one free S-300 reinforcement before the cruise launch", () => {
  const random = createDeterministicRandom("campaign-s300-reinforcement");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  applyCampaignMissionOpening(game);
  game = startAttackNow(game, () => random.next());
  game = advanceSimulation(game, 180_000, () => random.next());
  game = advanceSimulation(game, 180_000, () => random.next());
  game = advanceSimulation(game, 149_000, () => random.next());
  assert.equal(game.campaign?.unlockedSystems.includes("s300"), false);
  assert.equal(game.storedBatteries.some((battery) => battery.kind === "s300"), false);
  game = advanceSimulation(game, 2_000, () => random.next());
  assert.equal(game.campaign?.unlockedSystems.includes("s300"), true);
  assert.equal(game.storedBatteries.filter((battery) => battery.kind === "s300").length, 1);
  assert.equal(game.log.some((entry) => entry.title === "Підкріплення прибуло"), true);
  game = advanceSimulation(game, 5_000, () => random.next());
  assert.equal(game.storedBatteries.filter((battery) => battery.kind === "s300").length, 1);
  const reinforcement = game.storedBatteries.find((battery) => battery.kind === "s300")!;
  game.campaign!.campaignWallet = 0;
  game.resources.budget = 0;
  game = deployStoredBattery(game, reinforcement.id, { lat: 48.2, lng: 34.7 });
  assert.equal(game.batteries.some((battery) => battery.id === reinforcement.id), true);
  assert.equal(game.campaign?.campaignWallet, 0);
});

test("live campaign launches from and animates a real launch zone", () => {
  const random = createDeterministicRandom("campaign-live-launch-zone");
  let game = createScenarioState(() => random.next(), "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  applyCampaignMissionOpening(game);
  game = startAttackNow(game, () => random.next());
  game = advanceSimulation(game, 31_000, () => random.next());
  const warningSector = game.launchSectors.find((sector) => sector.state === "warning");
  assert.ok(warningSector);
  assert.ok(warningSector.lastLaunchCoordinates);
  assert.equal(game.liveThreats.length, 0);
  game = advanceSimulation(game, 15_000, () => random.next());
  const threat = game.liveThreats[0];
  assert.ok(threat);
  assert.notEqual(threat.launchSectorId, threat.routeId);
  assert.equal(sectorSupportsThreat(game.launchSectors.find((sector) => sector.id === threat.launchSectorId)!, threat.kind), true);
  assert.deepEqual(threat.routeWaypoints?.[0], threat.origin);
  const activeSector = game.launchSectors.find((sector) => sector.id === threat.launchSectorId)!;
  assert.equal(activeSector.state, "launching");
  assert.deepEqual(activeSector.lastLaunchCoordinates, threat.origin);
});

test("campaign cruise missiles receive an early track and complete their authored route", () => {
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
  assert.equal(cruise.launchSectorId, "astrakhan_air_corridor");
  game = advanceSimulation(game, 10_000, () => random.next());
  assert.equal(game.liveThreats.find((threat) => threat.id === cruise.id)?.revealed, true);
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
  game.campaign!.intermission = true;
  const before = game.campaign!.campaignWallet;
  game = serviceCampaignBattery(game, battery.id, "repair");
  assert.equal(battery.health, 100);
  assert.ok(game.campaign!.campaignWallet < before);
  const afterRepair = game.campaign!.campaignWallet;
  game = serviceCampaignBattery(game, battery.id, "resupply", .5);
  assert.ok((battery.currentAmmo as number) > 0);
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
  assert.equal(game.campaign?.spawnCursor, 29);
  assert.equal(game.campaign?.intermission, true);
  assert.equal(game.campaign?.previousMissionResults.length, 1);
  assert.equal(game.campaign?.previousMissionResults[0].totalTargets, 29);
  assert.equal(game.liveThreats.length, 0);
});
