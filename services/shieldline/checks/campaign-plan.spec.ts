import assert from "node:assert/strict";
import test from "node:test";
import { campaignMissionsPlan, campaignRouteTemplates, getCampaignMission, missionTargetCount } from "../src/data/campaignPlan";
import { advanceCampaignMission, applyCampaignMissionOpening, buildCampaignSpawnEvents, createCampaignState, finalizeCampaignMission, generateCampaignRoute, recordCampaignKill, routeHasSelfIntersection, serviceCampaignBattery } from "../src/game/campaignMeta";
import { createDeterministicRandom } from "../src/game/deterministicRandom";
import { createScenarioState } from "../src/game/initialState";
import { advanceSimulation, placeBattery, startAttackNow } from "../src/game/liveSimulation";

test("campaign catalog matches the five authored missions and target budgets", () => {
  assert.equal(campaignRouteTemplates.length, 30);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.title), ["Перший контакт", "Південний коридор", "Східна дуга", "Насичення", "Масована ніч"]);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.durationMinutes), [15, 35, 45, 50, 60]);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.grant), [38, 32, 48, 70, 100]);
  assert.deepEqual(campaignMissionsPlan.map((mission) => mission.rewardCap), [18, 35, 55, 80, 120]);
  assert.deepEqual(campaignMissionsPlan.map(missionTargetCount), [16, 41, 58, 78, 103]);
  assert.equal(campaignMissionsPlan.slice(0, 3).some((mission) => mission.waves.some((wave) => wave.threatKind === "iskander")), false);
  assert.equal(campaignMissionsPlan.slice(3).every((mission) => mission.waves.some((wave) => wave.threatKind === "iskander")), true);
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
});

test("campaign economy defers capped kill rewards and preserves units between missions", () => {
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
  for (let index = 0; index < 30; index += 1) recordCampaignKill(game, "parodiya", 1);
  game.interceptions = 16;
  const result = finalizeCampaignMission(game)!;
  assert.equal(result.killReward, getCampaignMission(1).rewardCap);
  assert.equal(result.bonusRewards, 25);
  assert.equal(result.walletAfterMission, 50);
  assert.equal(mvg.currentAmmo, 3);
  assert.equal(mvg.health, 76);
  assert.equal(mvg.experienceLevel, 1);
  assert.deepEqual(mvg.position, originalPosition);

  game = advanceCampaignMission(game);
  assert.equal(game.campaign?.missionIndex, 2);
  assert.equal(game.resources.budget, 82);
  assert.equal(game.batteries.find((battery) => battery.id === mvg.id)?.currentAmmo, 3);
  assert.ok(game.campaign?.unlockedSystems.includes("gepard"));
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
  assert.equal(game.campaign?.spawnCursor, 16);
  assert.equal(game.campaign?.intermission, true);
  assert.equal(game.campaign?.previousMissionResults.length, 1);
  assert.equal(game.campaign?.previousMissionResults[0].totalTargets, 16);
  assert.equal(game.liveThreats.length, 0);
});
