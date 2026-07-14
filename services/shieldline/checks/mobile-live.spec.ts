import assert from "node:assert/strict";
import test from "node:test";
import { BATTLE_NOTICE_DURATION_MS, preferBattleNotice } from "../src/game/battleNotices";
import { batteryCoverageState, batteryCoverageUnavailable } from "../src/game/coverageVisuals";
import type { IntelEntry } from "../src/types/game";

test("empty kinetic batteries use a distinct danger state while maintenance remains warning", () => {
  assert.equal(batteryCoverageUnavailable({ status: "ready", currentAmmo: 4 }), false);
  assert.equal(batteryCoverageUnavailable({ status: "reloading", currentAmmo: 0 }), true);
  assert.equal(batteryCoverageUnavailable({ status: "maintenance", currentAmmo: 4 }), true);
  assert.equal(batteryCoverageState({ status: "reloading", currentAmmo: 0 }), "empty");
  assert.equal(batteryCoverageState({ status: "maintenance", currentAmmo: 4 }), "maintenance");
  assert.equal(batteryCoverageState({ status: "ready", currentAmmo: 4 }), "ready");
});

test("infinite-ammo radars are orange only during maintenance", () => {
  assert.equal(batteryCoverageUnavailable({ status: "ready", currentAmmo: "infinite" }), false);
  assert.equal(batteryCoverageUnavailable({ status: "maintenance", currentAmmo: "infinite" }), true);
});

test("launch notifications replace detections and remain visible for four seconds", () => {
  const detection = { id: "detection", eventType: "detection", locationLabel: "kharkiv" } as IntelEntry;
  const launch = { id: "launch", eventType: "launch", locationLabel: "kursk" } as IntelEntry;

  assert.equal(BATTLE_NOTICE_DURATION_MS, 4_000);
  assert.equal(preferBattleNotice(detection, launch), launch);
  assert.equal(preferBattleNotice(launch, detection), launch);
});
