import assert from "node:assert/strict";
import test from "node:test";
import { BATTLE_NOTICE_DURATION_MS, preferBattleNotice, selectBattleNotice } from "../src/game/battleNotices";
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

test("zero-ammo sensors remain available and only switch tone during maintenance", () => {
  assert.equal(batteryCoverageState({ status: "ready", currentAmmo: 0 }, 0), "ready");
  assert.equal(batteryCoverageUnavailable({ status: "ready", currentAmmo: 0 }, 0), false);
  assert.equal(batteryCoverageState({ status: "maintenance", currentAmmo: 0 }, 0), "maintenance");
  assert.equal(batteryCoverageUnavailable({ status: "maintenance", currentAmmo: 0 }, 0), true);
});

test("launch notifications replace detections and remain visible for four seconds", () => {
  const detection = { id: "detection", eventType: "detection", locationLabel: "kharkiv" } as IntelEntry;
  const launch = { id: "launch", eventType: "launch", locationLabel: "kursk" } as IntelEntry;

  assert.equal(BATTLE_NOTICE_DURATION_MS, 4_000);
  assert.equal(preferBattleNotice(detection, launch), launch);
  assert.equal(preferBattleNotice(launch, detection), launch);
});

test("launch notifications win when offline simulation emits a launch and detection in one frame", () => {
  const launch = { id: "launch", eventType: "launch", locationLabel: "kursk" } as IntelEntry;
  const detection = { id: "detection", eventType: "detection", locationLabel: "kharkiv" } as IntelEntry;

  assert.equal(selectBattleNotice([detection, launch]), launch);
  assert.equal(selectBattleNotice([launch, detection]), launch);
});
