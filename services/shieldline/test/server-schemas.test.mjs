import assert from "node:assert/strict";
import test from "node:test";
import { normalizeNickname, parseAnalyticsEvent, parseAuthRegistration, parseOperationCommand, parseOperationInput, parsePlayerProgress } from "../serverSchemas.mjs";

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

test("analytics contract limits event names and platform dimensions", () => {
  const event = parseAnalyticsEvent({ eventName: "campaign.operation.completed", channel: "pwa", sessionId: "session-123", occurredAt: "2026-07-10T12:00:00.000Z", properties: { result: "victory", impacts: 0 } });
  assert.equal(event.channel, "pwa");
  assert.throws(() => parseAnalyticsEvent({ ...event, eventName: "unknown.event" }));
});

test("auth schema normalizes Unicode nicknames and rejects reserved names", () => {
  assert.equal(normalizeNickname("  СОКІЛ   01  "), "сокіл 01");
  const parsed = parseAuthRegistration({ nickname: "  Сокіл_01  ", deviceToken: "a".repeat(43), consentAccepted: true, consentVersion: "2026-07-15" });
  assert.equal(parsed.nickname, "Сокіл_01");
  assert.throws(() => parseAuthRegistration({ nickname: "ShieldLine", deviceToken: "a".repeat(43), consentAccepted: true, consentVersion: "v1" }), /validation/);
});

test("player progress accepts revisioned account snapshots", () => {
  assert.deepEqual(parsePlayerProgress({ baseRevision: 4, state: { game: { campaign: { missionIndex: 3 } } } }), { baseRevision: 4, state: { game: { campaign: { missionIndex: 3 } } } });
  assert.throws(() => parsePlayerProgress({ baseRevision: -1, state: {} }), /validation/);
});
