import assert from "node:assert/strict";
import test from "node:test";
import { createInitialState } from "../src/game/initialState.ts";
import { createDeterministicRandom } from "../src/game/deterministicRandom.ts";
import {
  SHOW_LAUNCH_DEBUG,
  createLaunchSectorState,
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
  const left = createInitialState(() => leftRandom.next());
  const right = createInitialState(() => rightRandom.next());
  const leftThreat = left.liveThreats[0];
  const rightThreat = right.liveThreats[0];
  const leftSector = left.launchSectors.find((sector) => sector.id === leftThreat.launchSectorId);
  const rightSector = right.launchSectors.find((sector) => sector.id === rightThreat.launchSectorId);

  assert.ok(leftSector && rightSector);
  assert.equal(sectorSupportsThreat(leftSector, leftThreat.kind), true);
  assert.equal(sectorSupportsThreat(rightSector, rightThreat.kind), true);
  assert.ok(distanceKm({ lat: leftSector.lat, lng: leftSector.lng }, leftThreat.origin) <= leftSector.radiusKm + 0.001);
  assert.ok(distanceKm({ lat: rightSector.lat, lng: rightSector.lng }, rightThreat.origin) <= rightSector.radiusKm + 0.001);
  assert.notDeepEqual(leftThreat.origin, rightThreat.origin);
});
