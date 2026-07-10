import assert from "node:assert/strict";
import test from "node:test";
import { simulateMission } from "../serverGame.mjs";

test("authoritative mission output is stable for a golden seed", () => {
  const left = simulateMission("golden-seed", "2026-07-10T00:00:00.000Z", 0.14, "campaign-night-01");
  const right = simulateMission("golden-seed", "2026-07-10T00:00:00.000Z", 0.14, "campaign-night-01");
  assert.deepEqual(left, right);
  assert.equal(left.events.at(0)?.type, "mission.started");
  assert.equal(left.events.at(-1)?.type, "mission.completed");
  assert.ok(left.events.some((event) => event.type === "launch.warning"));
  assert.ok(left.events.some((event) => event.type === "threat.launched"));
  assert.ok(left.events.some((event) => event.type === "battery.fired"));
  assert.equal(left.simVersion, "2.0.0");
  assert.equal(left.snapshots.length, 2);
});
