import { afterEach, describe, expect, it, vi } from "vitest";
import { loadConfig } from "../src/config.js";
import {
  normalizeTrack,
  type OfficialAlertEvent,
  type Zone,
} from "../src/engine/index.js";
import { Runtime } from "../src/runtime.js";
import type { Store } from "../src/store.js";
import type { SourceHealth } from "../src/ingestion/index.js";

const zone: Zone = {
  id: "synthetic-zone",
  userId: "synthetic-user",
  label: "Зона A",
  lat: 0,
  lon: 0,
  radiusKm: 5,
  enabled: true,
  oblast: "Тестова область",
  regionUid: "31",
};
const config = () =>
  loadConfig({
    NODE_ENV: "test",
    OBRIY_ENCRYPTION_KEY: "a".repeat(64),
    OBRIY_ADMIN_TOKEN: "x".repeat(40),
    OBRIY_COLLECTORS_ENABLED: "false",
    OBRIY_TELEGRAM_MODE: "disabled",
  });
function storeStub(overrides: Record<string, unknown> = {}): Store {
  return {
    acquireLeader: vi.fn(async () => true),
    cleanup: vi.fn(async () => undefined),
    setRuntime: vi.fn(async () => undefined),
    tracks: vi.fn(async () => []),
    zones: vi.fn(async () => []),
    activeAlerts: vi.fn(async () => []),
    recordAssessment: vi.fn(async () => undefined),
    ...overrides,
  } as unknown as Store;
}
function source(runtime: Runtime, health: SourceHealth): void {
  runtime.neptun = {
    health: () => health,
    stop: async () => undefined,
  } as unknown as NonNullable<Runtime["neptun"]>;
}
function privateRuntime(runtime: Runtime): {
  officialFor: (zone: Zone, events: OfficialAlertEvent[]) => boolean;
  evaluate: (eventKey: string, onlyTrackId?: string) => Promise<void>;
} {
  return runtime as unknown as {
    officialFor: (zone: Zone, events: OfficialAlertEvent[]) => boolean;
    evaluate: (eventKey: string, onlyTrackId?: string) => Promise<void>;
  };
}
function official(patch: Partial<OfficialAlertEvent> = {}): OfficialAlertEvent {
  return {
    provider: "alerts.in.ua",
    externalId: "synthetic-alert",
    regionUid: "31",
    raionUid: "31",
    raion: "Район A",
    oblast: "Тестова область",
    kind: "air_raid",
    active: true,
    updatedAt: new Date().toISOString(),
    ingestedAt: new Date().toISOString(),
    ...patch,
  };
}
afterEach(() => vi.restoreAllMocks());

describe("runtime source transport freshness", () => {
  it("accepts a current WebSocket heartbeat without requiring a new track mutation", () => {
    const runtime = new Runtime(config(), storeStub());
    source(runtime, {
      state: "live",
      transport: "websocket",
      lastSuccessAt: new Date(Date.now() - 120000).toISOString(),
      lastEventAt: new Date().toISOString(),
    });
    expect(runtime.sourceFresh()).toBe(true);
  });
  it("does not trust disconnected or expired transport state", () => {
    const runtime = new Runtime(config(), storeStub());
    source(runtime, {
      state: "degraded",
      transport: "websocket",
      lastSuccessAt: new Date().toISOString(),
      lastEventAt: new Date().toISOString(),
    });
    expect(runtime.sourceFresh()).toBe(false);
    source(runtime, {
      state: "live",
      transport: "websocket",
      lastSuccessAt: new Date(Date.now() - 120000).toISOString(),
      lastEventAt: new Date(Date.now() - 120000).toISOString(),
    });
    expect(runtime.sourceFresh()).toBe(false);
  });
  it("uses successful fetch time for REST fallback", () => {
    const runtime = new Runtime(config(), storeStub());
    source(runtime, {
      state: "live",
      transport: "rest",
      lastSuccessAt: new Date().toISOString(),
    });
    expect(runtime.sourceFresh()).toBe(true);
    source(runtime, {
      state: "live",
      transport: "rest",
      lastSuccessAt: new Date(Date.now() - 120000).toISOString(),
      lastEventAt: new Date().toISOString(),
    });
    expect(runtime.sourceFresh()).toBe(false);
  });
});

describe("official alerts retain administrative scope", () => {
  it("matches the configured UID but rejects another raion in the same oblast", () => {
    const runtime = privateRuntime(new Runtime(config(), storeStub()));
    expect(runtime.officialFor(zone, [official()])).toBe(true);
    expect(
      runtime.officialFor(zone, [
        official({ regionUid: "32", raionUid: "32", raion: "Район B" }),
      ]),
    ).toBe(false);
  });
  it("does not expand a raion or locality alert to a zone with only oblast metadata", () => {
    const runtime = privateRuntime(new Runtime(config(), storeStub()));
    const oblastZone = { ...zone, regionUid: undefined };
    expect(runtime.officialFor(oblastZone, [official()])).toBe(false);
    expect(
      runtime.officialFor(oblastZone, [
        official({
          raion: undefined,
          raionUid: undefined,
          locality: "Тестове місто",
        }),
      ]),
    ).toBe(false);
    expect(
      runtime.officialFor(oblastZone, [
        official({
          provider: "neptun",
          regionUid: undefined,
          raionUid: "test:a",
        }),
      ]),
    ).toBe(false);
  });
  it("permits an oblast-wide alert and excludes inactive/non-air-raid alerts", () => {
    const runtime = privateRuntime(new Runtime(config(), storeStub()));
    const wholeOblast = official({
      regionUid: "16",
      raionUid: undefined,
      raion: undefined,
    });
    expect(runtime.officialFor(zone, [wholeOblast])).toBe(true);
    expect(runtime.officialFor(zone, [{ ...wholeOblast, active: false }])).toBe(
      false,
    );
    expect(
      runtime.officialFor(zone, [
        { ...wholeOblast, kind: "artillery_shelling" },
      ]),
    ).toBe(false);
  });
});

describe("runtime evaluation scope and fatal leader loss", () => {
  it("evaluates only the changed track on an upsert; full passes still cover every track", async () => {
    const now = new Date();
    const make = (id: string) =>
      normalizeTrack(
        {
          id,
          type: "uav",
          lat: 0,
          lon: -0.2,
          status: "active",
          positionQuality: "confirmed",
          confidenceLevel: "high",
          updatedAt: now.toISOString(),
          confirmedAt: now.toISOString(),
        },
        now,
      );
    const tracks = [make("synthetic-a"), make("synthetic-b")];
    const recordAssessment = vi.fn(async (..._args: unknown[]) => undefined);
    const runtime = new Runtime(
      config(),
      storeStub({
        tracks: vi.fn(async () => tracks),
        zones: vi.fn(async () => [zone]),
        recordAssessment,
      }),
    );
    source(runtime, {
      state: "live",
      transport: "websocket",
      lastSuccessAt: now.toISOString(),
      lastEventAt: now.toISOString(),
    });
    await privateRuntime(runtime).evaluate(
      "upsert:synthetic-a",
      tracks[0]!.internalId,
    );
    expect(recordAssessment).toHaveBeenCalledTimes(1);
    expect(recordAssessment.mock.calls[0]?.[1]).toMatchObject({
      internalId: tracks[0]!.internalId,
    });
    recordAssessment.mockClear();
    await privateRuntime(runtime).evaluate("age:full-pass");
    expect(recordAssessment).toHaveBeenCalledTimes(2);
  });
  it("invokes the explicit fatal callback when the leader connection is lost", async () => {
    let lost: (() => void) | undefined;
    const onFatal = vi.fn();
    const store = storeStub({
      acquireLeader: vi.fn(async (callback: () => void) => {
        lost = callback;
        return true;
      }),
    });
    const runtime = new Runtime(config(), store, onFatal);
    try {
      await runtime.start();
      expect(runtime.leader).toBe(true);
      expect(lost).toBeTypeOf("function");
      lost!();
      await vi.waitFor(() => expect(onFatal).toHaveBeenCalledTimes(1));
      expect(runtime.leader).toBe(false);
    } finally {
      await runtime.stop();
    }
  });
});
