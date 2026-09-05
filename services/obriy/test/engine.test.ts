import { describe, expect, it } from "vitest";
import {
  angularDifference,
  assess,
  DEFAULT_ENGINE_CONFIG,
  destinationPoint,
  distanceBand,
  evidenceScore,
  extrapolate,
  haversineDistance,
  initialBearing,
  normalizeOfficialAlerts,
  normalizeTrack,
  riskScore,
  transition,
  uncertaintyAt,
  type AlertState,
  type RiskAssessment,
  type Zone,
} from "../src/engine/index.js";

const clock = new Date("2026-09-05T12:00:00.000Z");
const zone: Zone = {
  id: "synthetic-zone",
  userId: "test-user",
  label: "Зона A",
  lat: 0,
  lon: 0,
  radiusKm: 5,
  enabled: true,
};
function rawTrack(patch: Record<string, unknown> = {}) {
  return {
    id: "synthetic-track",
    type: "uav",
    lat: 0,
    lon: -0.2,
    velocity: { bearingDeg: 90, speedKmh: 150 },
    confirmedAt: clock.toISOString(),
    updatedAt: clock.toISOString(),
    status: "active",
    positionQuality: "confirmed",
    confidenceLevel: "high",
    uncertaintyKm: 2,
    sourceCount: 3,
    ...patch,
  };
}
function candidate(
  score: number,
  level: RiskAssessment["level"],
  second: number,
): RiskAssessment {
  const now = new Date(clock.getTime() + second * 1000);
  const track = normalizeTrack(
    rawTrack({ updatedAt: now.toISOString(), confirmedAt: now.toISOString() }),
    now,
  );
  return { ...assess(track, zone, now, true), score, level };
}

describe("geodesic geometry", () => {
  it("has zero self-distance and symmetric finite antipodal distances", () => {
    expect(haversineDistance(zone, zone)).toBe(0);
    expect(
      haversineDistance({ lat: 0, lon: 0 }, { lat: 0, lon: 180 }),
    ).toBeCloseTo(Math.PI * 6371.0088, 6);
    expect(haversineDistance({ lat: 30, lon: 20 }, { lat: -20, lon: 40 })).toBe(
      haversineDistance({ lat: -20, lon: 40 }, { lat: 30, lon: 20 }),
    );
  });
  it("computes bearings, wrapped differences and forward destinations across the date line", () => {
    expect(initialBearing(zone, { lat: 0, lon: 1 })).toBe(90);
    expect(initialBearing(zone, { lat: 1, lon: 0 })).toBe(0);
    expect(angularDifference(359, 1)).toBe(2);
    expect(angularDifference(-721, 721)).toBe(2);
    const destination = destinationPoint({ lat: 0, lon: 179.9 }, 90, 30);
    expect(destination.lon).toBeLessThan(-179);
    expect(haversineDistance({ lat: 0, lon: 179.9 }, destination)).toBeCloseTo(
      30,
      8,
    );
  });
  it("rejects malformed coordinates and motion", () => {
    expect(() => haversineDistance({ lat: Infinity, lon: 0 }, zone)).toThrow(
      "Invalid geographic point",
    );
    expect(() => destinationPoint(zone, NaN, 10)).toThrow(
      "Invalid geodesic motion",
    );
  });
  it("uses coarse distance bands at increasing distance", () => {
    expect([1, 15, 25, 40, 60, 90, 120].map(distanceBand)).toEqual([
      "<10 км",
      "10–20 км",
      "20–30 км",
      "30–50 км",
      "50–75 км",
      "75–100 км",
      ">100 км",
    ]);
  });
});

describe("upstream normalization", () => {
  it("preserves unknown fields and type while using a stable track UUID", () => {
    const first = normalizeTrack(
      rawTrack({ type: "future-type", newAttribute: { value: 1 } }),
      clock,
    );
    const replay = normalizeTrack(
      rawTrack({ type: "future-type", newAttribute: { value: 1 } }),
      clock,
    );
    expect(first).toEqual(replay);
    expect(first.internalId).toMatch(/^[a-f0-9-]{14}5/);
    expect(first.threat).toMatchObject({
      type: "other",
      upstreamType: "future-type",
    });
    expect(first.raw?.newAttribute).toEqual({ value: 1 });
  });
  it("normalizes headings without inventing unavailable motion", () => {
    expect(
      normalizeTrack(
        rawTrack({ velocity: { bearingDeg: -450, speedKmh: 150 } }),
        clock,
      ).motion.headingDeg,
    ).toBe(270);
    expect(
      normalizeTrack(
        rawTrack({ velocity: undefined, heading: 42, presumptiveCourse: true }),
        clock,
      ).motion,
    ).toMatchObject({ headingDeg: 42, speedKmh: undefined, presumptive: true });
    expect(
      normalizeTrack(
        rawTrack({ velocity: { bearingDeg: 90, speedKmh: -1 } }),
        clock,
      ).motion.speedKmh,
    ).toBeUndefined();
    expect(
      normalizeTrack(
        rawTrack({ velocity: { bearingDeg: 90, speedKmh: 1e9 } }),
        clock,
      ).motion.speedKmh,
    ).toBeUndefined();
  });
  it("treats documented zero target count as unspecified", () => {
    expect(
      normalizeTrack(rawTrack({ count: 0 }), clock).threat.groupCount,
    ).toBeUndefined();
    expect(
      normalizeTrack(rawTrack({ count: 2 }), clock).threat.groupCount,
    ).toBe(2);
  });
  it.each([NaN, Infinity, -Infinity, 91, -91, "12"])(
    "quarantines invalid latitude %s without including it in the error",
    (lat) => {
      expect(() => normalizeTrack(rawTrack({ lat }), clock)).toThrow(
        "Invalid upstream track schema",
      );
    },
  );
  it("rejects future observation anchors, reversed timestamps and far-future updates", () => {
    expect(() =>
      normalizeTrack(
        rawTrack({ confirmedAt: new Date(clock.getTime() + 1).toISOString() }),
        clock,
      ),
    ).toThrow("Invalid upstream timestamp");
    expect(() =>
      normalizeTrack(rawTrack({ updatedAt: "2026-09-05T11:59:59Z" }), clock),
    ).toThrow("Invalid upstream timestamp order");
    expect(() =>
      normalizeTrack(rawTrack({ updatedAt: "2099-01-01T00:00:00Z" }), clock),
    ).toThrow("Invalid upstream timestamp");
    expect(() =>
      normalizeTrack(rawTrack({ updatedAt: "2026-09-05 12:00:00" }), clock),
    ).toThrow("Invalid upstream timestamp");
  });
  it("removes centroid coordinates and rejects hostile optional booleans", () => {
    const track = normalizeTrack(rawTrack({ areaOnly: true }), clock);
    expect(track.position.lat).toBeUndefined();
    expect(track.position.lon).toBeUndefined();
    expect(() =>
      normalizeTrack(rawTrack({ advisory: "false" }), clock),
    ).toThrow();
  });
  it("maps verified NEPTUN administrative alerts separately from tracks", () => {
    const alerts = normalizeOfficialAlerts(
      {
        version: 1,
        updatedAt: clock.toISOString(),
        oblasts: [
          {
            key: "synthetic-oblast",
            name: "Тестова область",
            oblast: "",
            since: clock.toISOString(),
          },
        ],
        raions: [
          {
            key: "synthetic-oblast:raion",
            name: "Тестовий район",
            oblast: "Тестова область",
            since: clock.toISOString(),
          },
        ],
      },
      "neptun",
      clock,
    );
    expect(alerts).toHaveLength(2);
    expect(alerts[0]).toMatchObject({
      regionUid: "synthetic-oblast",
      oblast: "Тестова область",
      active: true,
      kind: "air_raid",
    });
    expect(alerts[1]).toMatchObject({
      raionUid: "synthetic-oblast:raion",
      raion: "Тестовий район",
    });
    expect(alerts[1]).not.toHaveProperty("position");
    expect(() =>
      normalizeOfficialAlerts({ oblasts: [], raions: null }, "neptun", clock),
    ).toThrow();
  });
  it("maps alerts.in.ua dates, identity and unknown types without positional confidence", () => {
    const alerts = normalizeOfficialAlerts(
      {
        alerts: [
          {
            id: 10,
            location_title: "Тестова область",
            location_type: "oblast",
            location_uid: "16",
            alert_type: "future_alert",
            started_at: clock.toISOString(),
            finished_at: null,
            updated_at: clock.toISOString(),
            calculated: false,
          },
        ],
      },
      "alerts.in.ua",
      clock,
    );
    expect(alerts[0]).toMatchObject({
      externalId: "10",
      regionUid: "16",
      kind: "unknown",
      active: true,
      calculated: false,
    });
    expect(
      normalizeOfficialAlerts({ alerts: [] }, "alerts.in.ua", clock),
    ).toEqual([]);
    expect(() => normalizeOfficialAlerts({}, "alerts.in.ua", clock)).toThrow();
  });
});

describe("conservative threat assessment", () => {
  it("predicts an approach and a real corridor with deterministic output", () => {
    const track = normalizeTrack(rawTrack(), clock);
    const result = assess(track, zone, clock, true);
    expect(result).toEqual(assess(track, zone, clock, true));
    expect(result.level).toBe("HIGH");
    expect(result.geometry.corridorIntersects).toBe(true);
    expect(result.explanationCodes).toContain("APPROACHING");
    expect(result.geometry.forecastHorizonSeconds).toBe(600);
    expect(result).not.toHaveProperty("eta");
  });
  it("does not call a near miss HIGH", () => {
    const start = destinationPoint(zone, 270, 33);
    const track = normalizeTrack(rawTrack({ ...start }), clock);
    const result = assess(track, zone, clock, true);
    expect(result.geometry.corridorIntersects).toBe(true);
    expect(result.geometry.strongCorridorIntersection).toBe(false);
    expect(result.level).toBe("WARNING");
    const miss = normalizeTrack(rawTrack({ lat: 1, lon: -0.2 }), clock);
    expect(assess(miss, zone, clock, true).geometry.corridorIntersects).toBe(
      false,
    );
    expect(assess(miss, zone, clock, true).level).not.toBe("HIGH");
  });
  it("never extrapolates or exposes personalized distance for areaOnly, across positions and confidences", () => {
    for (let i = 0; i < 100; i++) {
      const track = normalizeTrack(
        rawTrack({
          areaOnly: true,
          lat: i % 90,
          lon: i,
          uncertaintyKm: i * 10,
          sourceCount: i,
          confidenceLevel: ["low", "medium", "high"][i % 3],
        }),
        clock,
      );
      const result = assess(track, zone, clock, true);
      expect(result.level).toBe("INFO");
      expect(result.geometry).toEqual({ corridorIntersects: false });
      expect(extrapolate(track, clock)).toBeNull();
      expect(uncertaintyAt(track, 100)).toBeUndefined();
    }
  });
  it("advisory, stale, unknown status and disabled zones cannot escalate", () => {
    for (const patch of [
      { advisory: true },
      { status: "stale" },
      { status: "future-status" },
    ]) {
      const result = assess(
        normalizeTrack(rawTrack(patch), clock),
        zone,
        clock,
        true,
      );
      expect(result.level).toBe("INFO");
      expect(result.escalationAllowed).toBe(false);
    }
    expect(
      assess(
        normalizeTrack(rawTrack(), clock),
        { ...zone, enabled: false },
        clock,
        true,
      ).escalationAllowed,
    ).toBe(false);
  });
  it("never says approaching without speed, anchor, heading, or known position quality", () => {
    for (const patch of [
      { velocity: undefined },
      { confirmedAt: undefined },
      { velocity: { speedKmh: 150 } },
      { positionQuality: "new-quality" },
    ]) {
      const result = assess(
        normalizeTrack(rawTrack(patch), clock),
        zone,
        clock,
        true,
      );
      expect(result.factors.approaching).toBe(0);
      expect(result.explanationCodes).not.toContain("APPROACHING");
      expect(result.level).toBe("INFO");
      expect(result.geometry.forecastHorizonSeconds).toBeUndefined();
    }
  });
  it("does not renew a forecast horizon when a source observation ages", () => {
    const track = normalizeTrack(rawTrack(), clock);
    const later = new Date(clock.getTime() + 300000);
    expect(
      assess(track, zone, later, false).geometry.forecastHorizonSeconds,
    ).toBe(300);
    const stale = assess(track, zone, new Date(clock.getTime() + 700000), true);
    expect(stale.level).toBe("INFO");
    expect(stale.escalationAllowed).toBe(false);
    expect(stale.factors.freshness).toBe(0);
    expect(extrapolate(track, new Date(clock.getTime() + 700000))).toEqual(
      extrapolate(track, new Date(clock.getTime() + 600000)),
    );
  });
  it("keeps uncertainty and source quantity separate from evidence confidence", () => {
    const normal = normalizeTrack(rawTrack({ uncertaintyKm: 2 }), clock);
    const uncertain = normalizeTrack(rawTrack({ uncertaintyKm: 100 }), clock);
    expect(evidenceScore(normal)).toBe(evidenceScore(uncertain));
    expect(assess(uncertain, zone, clock, true).level).not.toBe("HIGH");
    expect(uncertaintyAt(normal, 300)).toBeGreaterThan(
      uncertaintyAt(normal, 0)!,
    );
    expect(
      evidenceScore(normalizeTrack(rawTrack({ sourceCount: 1000 }), clock)),
    ).toBe(evidenceScore(normalizeTrack(rawTrack({ sourceCount: 5 }), clock)));
  });
  it("freshness never improves without new source evidence, and finite inputs yield bounded scores", () => {
    const track = normalizeTrack(rawTrack(), clock);
    let previous = 1;
    for (let seconds = 0; seconds <= 900; seconds += 15) {
      const result = assess(
        track,
        zone,
        new Date(clock.getTime() + seconds * 1000),
        false,
      );
      expect(result.factors.freshness).toBeLessThanOrEqual(previous);
      expect(Number.isFinite(result.score)).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(0);
      expect(result.score).toBeLessThanOrEqual(100);
      previous = result.factors.freshness;
    }
  });
  it("official regional context changes risk by at most five points and never adds position", () => {
    const track = normalizeTrack(rawTrack({ velocity: undefined }), clock);
    const noAlert = assess(track, zone, clock, false),
      alert = assess(track, zone, clock, true);
    expect(alert.score - noAlert.score).toBeCloseTo(5);
    expect(alert.factors.evidence).toBe(noAlert.factors.evidence);
    expect(alert.level).toBe("INFO");
    expect(
      riskScore({
        evidence: 1,
        freshness: 1,
        proximity: 1,
        approaching: 1,
        corridorHit: 1,
        officialContext: 1,
      }),
    ).toBe(100);
  });
});

describe("persistent hysteresis and notification deduplication", () => {
  it("requires two distinct source observations, deduplicates replay and resists aging escalation", () => {
    const first = candidate(85, "HIGH", 0);
    const one = transition(null, first, { eventKey: "event-1" });
    expect(one.state.currentLevel).toBe("INFO");
    expect(one.notify).toBe(false);
    expect(transition(one.state, first, { eventKey: "event-1" }).reason).toBe(
      "DUPLICATE_EVENT",
    );
    const aged = {
      ...first,
      evaluatedAt: new Date(clock.getTime() + 1000).toISOString(),
      assessmentId: "aged",
    };
    expect(transition(one.state, aged).state.currentLevel).toBe("INFO");
    const two = transition(one.state, candidate(85, "HIGH", 2), {
      eventKey: "event-2",
    });
    expect(two.state.currentLevel).toBe("HIGH");
    expect(two.notify).toBe(true);
    expect(transition(two.state, first, { eventKey: "event-1" }).reason).toBe(
      "DUPLICATE_EVENT",
    );
    expect(
      transition(two.state, candidate(85, "HIGH", 1), { eventKey: "old-event" })
        .reason,
    ).toBe("OUT_OF_ORDER_EVENT");
  });
  it("does not spam at threshold oscillations and exits after three below-threshold observations", () => {
    let state: AlertState | null = null;
    let notifications = 0;
    for (let second = 0; second < 20; second++) {
      const result = transition(
        state,
        candidate(
          second % 2 ? 66 : 64,
          second % 2 ? "WARNING" : "WATCH",
          second,
        ),
      );
      state = result.state;
      notifications += Number(result.notify);
    }
    expect(notifications).toBe(0);
    state = transition(null, candidate(70, "WARNING", 30)).state;
    state = transition(state, candidate(70, "WARNING", 31)).state;
    expect(state.currentLevel).toBe("WARNING");
    for (let second = 32; second < 34; second++) {
      state = transition(state, candidate(40, "INFO", second)).state;
      expect(state.currentLevel).toBe("WARNING");
    }
    state = transition(state, candidate(40, "INFO", 34)).state;
    expect(state.currentLevel).toBe("INFO");
  });
  it("retains threshold hysteresis inside the exit band", () => {
    let state = transition(null, candidate(70, "WARNING", 0)).state;
    state = transition(state, candidate(70, "WARNING", 1)).state;
    for (let second = 2; second < 8; second++)
      state = transition(state, candidate(60, "WATCH", second)).state;
    expect(state.currentLevel).toBe("WARNING");
  });
  it("caps advisory and area-only state immediately and never escalates stale input", () => {
    let state = transition(null, candidate(90, "HIGH", 0)).state;
    state = transition(state, candidate(90, "HIGH", 1)).state;
    const advisory = {
      ...candidate(90, "INFO", 2),
      explanationCodes: ["ADVISORY"] as const,
      escalationAllowed: false,
    };
    expect(
      transition(state, {
        ...advisory,
        explanationCodes: [...advisory.explanationCodes],
      }).state.currentLevel,
    ).toBe("INFO");
    const stale = {
      ...candidate(90, "HIGH", 3),
      explanationCodes: ["STALE"] as RiskAssessment["explanationCodes"],
      escalationAllowed: false,
    };
    expect(transition(null, stale).state.currentLevel).toBe("INFO");
  });
  it("requires source resolution grace and a previously sent warning for a resolution summary", () => {
    let state = transition(null, candidate(90, "HIGH", 0)).state;
    state = transition(state, candidate(90, "HIGH", 1)).state;
    const resolution = {
      ...candidate(0, "INFO", 10),
      resolved: true,
      escalationAllowed: false,
    };
    const pending = transition(state, resolution);
    expect(pending.notify).toBe(false);
    const complete = transition(
      pending.state,
      {
        ...resolution,
        evaluatedAt: new Date(clock.getTime() + 71000).toISOString(),
      },
      { eventKey: "resolution-tick" },
    );
    expect(complete.state.currentLevel).toBe("RESOLVED");
    expect(complete.notify).toBe(true);
    const quiet = transition(null, resolution).state;
    expect(
      transition(
        quiet,
        {
          ...resolution,
          evaluatedAt: new Date(clock.getTime() + 71000).toISOString(),
        },
        { eventKey: "quiet-resolution" },
      ).notify,
    ).toBe(false);
  });
  it("bounds notifications by cooldown, except material upward escalation", () => {
    let state: AlertState | null = null;
    const notifications: number[] = [];
    for (let second = 0; second <= 1000; second += 10) {
      const result = transition(state, candidate(85, "HIGH", second));
      state = result.state;
      if (result.notify) notifications.push(second);
    }
    expect(notifications).toEqual([10, 910]);
    expect(state?.recentEventKeys?.length).toBe(32);
  });
  it("configuration is versioned and replay converges to identical state", () => {
    const run = () =>
      [45, 46, 67, 68, 85, 86, 60, 40, 20].reduce<AlertState | null>(
        (state, score, index) =>
          transition(
            state,
            candidate(
              score,
              score >= 80
                ? "HIGH"
                : score >= 65
                  ? "WARNING"
                  : score >= 45
                    ? "WATCH"
                    : "INFO",
              index,
            ),
          ).state,
        null,
      );
    expect(run()).toEqual(run());
    expect(DEFAULT_ENGINE_CONFIG.version).toBe("obriy-initial-1");
  });
});
