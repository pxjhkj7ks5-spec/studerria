import assert from "node:assert/strict";
import test from "node:test";
import { createDeterministicRandom } from "../src/game/deterministicRandom.ts";
import { campaignMissions } from "../src/data/missions.ts";
import { runDeterministicMission } from "../src/game/deterministicMission.ts";
import {
  CAMPAIGN_RANDOM_LAUNCH_SECTOR_IDS,
  SHOW_LAUNCH_DEBUG,
  createLaunchSectorState,
  generateLaunchOrigin,
  launchSectors,
  pickWeightedSector,
  randomPointInSector,
  sectorSupportsThreat,
} from "../src/game/launchSystem.mjs";

function distanceKm(left, right) {
  const radians = (value) => value * Math.PI / 180;
  const dLat = radians(right.lat - left.lat);
  const dLng = radians(right.lng - left.lng);
  const lat1 = radians(left.lat);
  const lat2 = radians(right.lat);
  const value = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLng / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(value), Math.sqrt(1 - value));
}

test("live mode uses the complete abstract launch-sector catalogue", () => {
  assert.equal(launchSectors.length, 20);
  assert.equal(new Set(launchSectors.map((sector) => sector.id)).size, launchSectors.length);
  assert.equal(SHOW_LAUNCH_DEBUG, false);
  assert.ok(launchSectors.every((sector) => sector.radiusKm >= 40 && sector.weight > 0 && sector.threats.length > 0 && sector.role));
  assert.ok(!launchSectors.some((sector) => ["drone-northwest", "otrk-northeast", "black-sea-ships"].includes(sector.id)));
});

test("random launch points are distributed inside the sector radius", () => {
  const sector = launchSectors.find((item) => item.id === "chauda_crimea");
  const values = [0.25, 0];
  const point = randomPointInSector(sector, () => values.shift());
  const distance = distanceKm({ lat: sector.lat, lng: sector.lng }, point);

  assert.ok(distance > sector.radiusKm * 0.49 && distance < sector.radiusKm * 0.51);
  for (let index = 0; index < 100; index += 1) {
    const random = createDeterministicRandom(`launch-radius-${index}`);
    const sample = randomPointInSector(sector, () => random.next());
    assert.ok(distanceKm({ lat: sector.lat, lng: sector.lng }, sample) <= sector.radiusKm + 0.001);
  }
});

test("weighted selection filters incompatible sectors before choosing", () => {
  const sectors = createLaunchSectorState();
  const droneSector = pickWeightedSector(sectors, "geran2", () => 0.73);
  const ballisticSector = pickWeightedSector(sectors, "iskander", () => 0.42);
  const cruiseSector = pickWeightedSector(sectors, "kalibr", () => 0.91);

  assert.equal(sectorSupportsThreat(droneSector, "geran2"), true);
  assert.equal(sectorSupportsThreat(ballisticSector, "iskander"), true);
  assert.equal(sectorSupportsThreat(cruiseSector, "kalibr"), true);
  assert.throws(() => pickWeightedSector(sectors, "unsupported-threat", () => 0.5), /No launch sector supports/);
});

test("separate live operations receive different compatible launch origins", () => {
  const leftRandom = createDeterministicRandom("live-operation-left");
  const rightRandom = createDeterministicRandom("live-operation-right");
  const left = generateLaunchOrigin(createLaunchSectorState(), "geran2", () => leftRandom.next());
  const right = generateLaunchOrigin(createLaunchSectorState(), "geran2", () => rightRandom.next());

  assert.equal(sectorSupportsThreat(left.sector, "geran2"), true);
  assert.equal(sectorSupportsThreat(right.sector, "geran2"), true);
  assert.ok(distanceKm({ lat: left.sector.lat, lng: left.sector.lng }, left.point) <= left.sector.radiusKm + 0.001);
  assert.ok(distanceKm({ lat: right.sector.lat, lng: right.sector.lng }, right.point) <= right.sector.radiusKm + 0.001);
  assert.notDeepEqual(left.point, right.point);
});

test("the single campaign mission randomizes launch points, threats and targets per operation", () => {
  const mission = campaignMissions[0];
  assert.equal(campaignMissions.length, 1);
  assert.deepEqual(mission.launchSectorIds, CAMPAIGN_RANDOM_LAUNCH_SECTOR_IDS);
  assert.equal(mission.waves.length, 0);
  assert.equal(mission.randomWaveCount, 6);
  const left = runDeterministicMission(mission, "campaign-sector-left");
  const right = runDeterministicMission(mission, "campaign-sector-right");
  const leftLaunches = left.events.filter((event) => event.type === "threat.launched");
  const rightLaunches = right.events.filter((event) => event.type === "threat.launched");

  assert.equal(leftLaunches.length, mission.randomWaveCount);
  for (const launch of leftLaunches) {
    const sector = launchSectors.find((item) => item.id === launch.sectorId);
    assert.ok(sector);
    assert.ok(CAMPAIGN_RANDOM_LAUNCH_SECTOR_IDS.includes(sector.id));
    assert.equal(sectorSupportsThreat(sector, String(launch.payload.threatKind)), true);
    const point = { lat: Number(launch.payload.originLat), lng: Number(launch.payload.originLng) };
    assert.ok(distanceKm({ lat: sector.lat, lng: sector.lng }, point) <= sector.radiusKm + 0.001);
  }
  assert.notDeepEqual(
    leftLaunches.map((event) => [event.payload.originLat, event.payload.originLng]),
    rightLaunches.map((event) => [event.payload.originLat, event.payload.originLng]),
  );
  assert.notDeepEqual(
    leftLaunches.map((event) => [event.payload.threatKind, event.payload.targetLat, event.payload.targetLng]),
    rightLaunches.map((event) => [event.payload.threatKind, event.payload.targetLat, event.payload.targetLng]),
  );
});
