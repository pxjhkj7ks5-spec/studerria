import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { serverCampaignMissions, simulateMission } from "../serverGame.mjs";
import { campaignMissions } from "../src/data/missions.ts";
import { runDeterministicMission } from "../src/game/deterministicMission.ts";
import { calculateDefenseBonus } from "../src/game/simulationCore.mjs";
import { flightDurationForDistance, routeDistanceKm, THREAT_FLIGHT_PROFILES, trimRouteToTrackedDistance } from "../src/game/threatFlightModel.mjs";

test("production image includes every authoritative simulation runtime module", async () => {
  const dockerfile = await readFile(new URL("../Dockerfile", import.meta.url), "utf8");
  assert.match(dockerfile, /src\/game\/simulationCore\.mjs/);
  assert.match(dockerfile, /src\/game\/launchSystem\.mjs/);
  assert.match(dockerfile, /src\/game\/campaignPacing\.mjs/);
  assert.match(dockerfile, /src\/game\/airDefenseRules\.mjs/);
  assert.match(dockerfile, /src\/game\/threatFlightModel\.mjs/);
  assert.match(dockerfile, /serverTelegramAuth\.mjs/);
});

test("server and browser campaign catalogs stay in parity", () => {
  const browserCatalog = campaignMissions.map(({ id, title, durationMinutes, grant, waves }) => ({
    id,
    title,
    durationMinutes,
    grant,
    waves: waves.map(({ threatKind, size, etaSeconds }) => ({ threatKind, size, etaSeconds })),
  }));
  const serverCatalog = serverCampaignMissions.map(({ id, title, durationMinutes, grant, waves }) => ({
    id,
    title,
    durationMinutes,
    grant,
    waves: waves.map(({ threatKind, size, etaSeconds }) => ({ threatKind, size, etaSeconds })),
  }));
  assert.deepEqual(serverCatalog, browserCatalog);
});

test("authoritative mission output is stable for a golden seed", () => {
  const left = simulateMission("golden-seed", "2026-07-10T00:00:00.000Z", 0.14, "campaign-night-01");
  const right = simulateMission("golden-seed", "2026-07-10T00:00:00.000Z", 0.14, "campaign-night-01");
  assert.deepEqual(left, right);
  assert.equal(left.events.at(0)?.type, "mission.started");
  assert.equal(left.events.at(-1)?.type, "mission.completed");
  assert.ok(left.events.some((event) => event.type === "launch.warning"));
  assert.ok(left.events.some((event) => event.type === "threat.launched"));
  assert.ok(left.events.some((event) => event.type === "track.detected"));
  assert.ok(left.events.some((event) => event.type === "battery.fired"));
  assert.equal(left.simVersion, "3.1.0");
  assert.equal(left.snapshots.length, 2);
  for (const launched of left.events.filter((event) => event.type === "threat.launched")) {
    const duration = Number(launched.payload.flightDurationMs);
    assert.equal(launched.payload.speedKph, THREAT_FLIGHT_PROFILES[launched.payload.threatKind].speedKph);
    const trackedRoute = trimRouteToTrackedDistance(launched.payload.threatKind, [
      { lat: launched.payload.originLat, lng: launched.payload.originLng },
      { lat: launched.payload.targetLat, lng: launched.payload.targetLng },
    ]);
    const distanceKm = routeDistanceKm(trackedRoute);
    assert.equal(duration, flightDurationForDistance(launched.payload.threatKind, launched.payload.speedKph, distanceKm));
    const impact = left.events.find((event) => event.waveId === launched.waveId && event.type === "impact");
    if (impact) assert.equal(impact.occurredAtMs - launched.occurredAtMs, duration);
    const interception = left.events.find((event) => event.waveId === launched.waveId && event.type === "interception");
    if (interception) {
      const interceptProgress = (interception.occurredAtMs - launched.occurredAtMs) / duration;
      assert.ok(interceptProgress >= 0.62 && interceptProgress <= 0.74);
    }
  }
});

test("browser offline and server adapters emit byte-identical campaign events", () => {
  const plan = {
    assetCount: 2,
    radarCount: 1,
    kineticCount: 1,
    averageReadiness: 88,
    assets: [
      { kind: "radar", cityId: "kyiv", readiness: 92 },
      { kind: "nasams", cityId: "kyiv", readiness: 84 },
    ],
  };
  const browserRun = runDeterministicMission(campaignMissions[0], "adapter-parity", plan);
  const serverRun = simulateMission("adapter-parity", "2026-07-09T00:00:00.000Z", calculateDefenseBonus(plan), campaignMissions[0].id, plan);
  assert.equal(JSON.stringify(browserRun.events), JSON.stringify(serverRun.events));
  assert.equal(JSON.stringify(browserRun.snapshots), JSON.stringify(serverRun.snapshots));
});
