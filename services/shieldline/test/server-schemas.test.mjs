import assert from "node:assert/strict";
import test from "node:test";
import { parseOperationCommand, parseOperationInput } from "../serverSchemas.mjs";

test("operation schemas accept versioned campaign plans and reject inconsistent counts", () => {
  const valid = {
    modeId: "campaign",
    missionId: "campaign-night-01",
    seed: "campaign-seed-01",
    simVersion: "2.1.0",
    plan: {
      assetCount: 2,
      radarCount: 1,
      kineticCount: 1,
      averageReadiness: 90,
      assets: [
        { kind: "radar", cityId: "kyiv", readiness: 90, position: { lat: 50.4, lng: 30.5 } },
        { kind: "buk", cityId: "kyiv", readiness: 90, position: { lat: 50.2, lng: 30.1 } },
      ],
    },
  };
  assert.equal(parseOperationInput(valid).plan.assets.length, 2);
  assert.throws(() => parseOperationInput({ ...valid, plan: { ...valid.plan, assetCount: 3 } }), (error) => error.statusCode === 422);
});

test("operation command schema enforces idempotency and revision fields", () => {
  assert.deepEqual(parseOperationCommand({ commandId: "command-123", baseRevision: 1, scope: { type: "operation" }, type: "asset.place", payload: {} }).commandId, "command-123");
  assert.throws(() => parseOperationCommand({ commandId: "x", baseRevision: 0, scope: { type: "operation" }, type: "asset.place", payload: {} }));
});
