import assert from "node:assert/strict";
import test from "node:test";
import { canApplyRemoteProgress, resolveProgressWriteConflict } from "../src/platform/accountProgressSync";

test("a revision conflict keeps the active local mission and rebases it onto the latest revision", () => {
  const local = {
    operationPhase: "running",
    game: {
      elapsedMs: 42_000,
      batteries: [{ id: "radar-1" }, { id: "nasams-1" }],
    },
  };
  const remote = {
    revision: 8,
    state: {
      operationPhase: "planning",
      game: {
        elapsedMs: 0,
        batteries: [] as Array<{ id: string }>,
      },
    },
  };

  const resolution = resolveProgressWriteConflict(local, remote);

  assert.equal(resolution.baseRevision, 8);
  assert.strictEqual(resolution.state, local);
  assert.deepEqual(resolution.state.game.batteries, [{ id: "radar-1" }, { id: "nasams-1" }]);
  assert.equal(resolution.shouldRetry, true);
});

test("an identical remote snapshot resolves a conflict without another write", () => {
  const state = { operationPhase: "planning", game: { elapsedMs: 0, batteries: [] } };
  const resolution = resolveProgressWriteConflict(state, { revision: 4, state: structuredClone(state) });

  assert.equal(resolution.baseRevision, 4);
  assert.equal(resolution.shouldRetry, false);
});

test("focus refresh cannot replace an operation that is already active on this device", () => {
  assert.equal(canApplyRemoteProgress({ operationPhase: "countdown" }), false);
  assert.equal(canApplyRemoteProgress({ operationPhase: "running" }), false);
  assert.equal(canApplyRemoteProgress({ operationPhase: "paused" }), false);
  assert.equal(canApplyRemoteProgress({ operationPhase: "planning" }), true);
  assert.equal(canApplyRemoteProgress({ operationPhase: "completed" }), true);
});
