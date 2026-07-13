import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { simulateMission } from "../serverGame.mjs";
import { campaignMissions } from "../src/data/missions.ts";
import { runDeterministicMission } from "../src/game/deterministicMission.ts";
import { calculateDefenseBonus } from "../src/game/simulationCore.mjs";

test("production image includes every authoritative simulation runtime module", async () => {
  const dockerfile = await readFile(new URL("../Dockerfile", import.meta.url), "utf8");
  assert.match(dockerfile, /src\/game\/simulationCore\.mjs/);
  assert.match(dockerfile, /src\/game\/launchSystem\.mjs/);
  assert.match(dockerfile, /src\/game\/campaignPacing\.mjs/);
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
  assert.equal(left.simVersion, "2.5.0");
  assert.equal(left.snapshots.length, 2);
  const windows = { geran2: [120_000, 180_000], gerbera: [120_000, 180_000], parodiya: [120_000, 180_000], kh101: [70_000, 110_000], kalibr: [70_000, 110_000], iskander: [20_000, 40_000] };
  for (const launched of left.events.filter((event) => event.type === "threat.launched")) {
    const duration = Number(launched.payload.flightDurationMs);
    const [minimum, maximum] = windows[launched.payload.threatKind];
    assert.ok(duration >= minimum && duration <= maximum);
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
  const serverRun = simulateMission("adapter-parity", "2026-07-09T00:00:00.000Z", calculateDefenseBonus(plan), campaignMissions[0].id);
  assert.equal(JSON.stringify(browserRun.events), JSON.stringify(serverRun.events));
  assert.equal(JSON.stringify(browserRun.snapshots), JSON.stringify(serverRun.snapshots));
});
