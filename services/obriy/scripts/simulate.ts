import assert from "node:assert/strict";
import {
  assess,
  destinationPoint,
  normalizeTrack,
  transition,
  type AlertState,
  type RiskAssessment,
  type Zone,
} from "../src/engine/index.js";

// All coordinates are synthetic points around the equator. No production data is read.
const epoch = Date.parse("2026-01-01T00:00:00.000Z");
const zone: Zone = {
  id: "simulated-zone",
  userId: "simulated-user",
  label: "Зона симулятора",
  lat: 0,
  lon: 0,
  radiusKm: 5,
  enabled: true,
};
interface Frame {
  seconds: number;
  distanceKm?: number;
  patch?: Record<string, unknown>;
  official?: boolean;
  eventKey?: string;
  score?: number;
  level?: RiskAssessment["level"];
}
interface ReplayResult {
  states: AlertState[];
  assessments: RiskAssessment[];
  notifications: number;
}

function replay(frames: Frame[]): ReplayResult {
  let state: AlertState | null = null;
  const result: ReplayResult = {
    states: [],
    assessments: [],
    notifications: 0,
  };
  for (const frame of frames) {
    const now = new Date(epoch + frame.seconds * 1000);
    const point = destinationPoint(zone, 270, frame.distanceKm ?? 20);
    const track = normalizeTrack(
      {
        id: "synthetic-object",
        type: "uav",
        ...point,
        status: "active",
        positionQuality: "confirmed",
        confidenceLevel: "high",
        sourceCount: 3,
        velocity: { bearingDeg: 90, speedKmh: 150 },
        uncertaintyKm: 2,
        confirmedAt: now.toISOString(),
        updatedAt: now.toISOString(),
        ...frame.patch,
      },
      now,
    );
    const assessment = assess(track, zone, now, frame.official ?? true);
    if (frame.score !== undefined) assessment.score = frame.score;
    if (frame.level !== undefined) assessment.level = frame.level;
    const next = transition(state, assessment, {
      now,
      eventKey: frame.eventKey,
    });
    state = next.state;
    result.states.push(state);
    result.assessments.push(assessment);
    result.notifications += Number(next.notify);
  }
  return result;
}

const scenarios: { name: string; verify: () => ReplayResult }[] = [
  {
    name: "direct approach: INFO → WATCH → WARNING → HIGH",
    verify: () => {
      const result = replay([
        {
          seconds: 0,
          distanceKm: 180,
          patch: { velocity: { bearingDeg: 270, speedKmh: 150 } },
        },
        { seconds: 2880, distanceKm: 60 },
        { seconds: 2904, distanceKm: 59 },
        { seconds: 3528, distanceKm: 33 },
        { seconds: 3530, distanceKm: 33 },
        { seconds: 3840, distanceKm: 20 },
        { seconds: 3864, distanceKm: 19 },
      ]);
      assert.deepEqual(
        [...new Set(result.states.map((s) => s.currentLevel))],
        ["INFO", "WATCH", "WARNING", "HIGH"],
      );
      // Two level increases and one nearer-distance-band update after the minimum gap.
      assert.equal(result.notifications, 3);
      return result;
    },
  },
  {
    name: "near miss: uncertainty corridor is not a strong intersection",
    verify: () => {
      const result = replay([
        { seconds: 0, distanceKm: 33 },
        { seconds: 2, distanceKm: 33 },
      ]);
      assert(
        result.assessments.every(
          (a) =>
            a.geometry.corridorIntersects &&
            !a.geometry.strongCorridorIntersection,
        ),
      );
      assert(result.states.every((s) => s.currentLevel !== "HIGH"));
      return result;
    },
  },
  {
    name: "turn away: three observations before de-escalation",
    verify: () => {
      const away = { velocity: { bearingDeg: 270, speedKmh: 150 } };
      const result = replay([
        { seconds: 0 },
        { seconds: 1 },
        { seconds: 2, patch: away },
        { seconds: 3, patch: away },
        { seconds: 4, patch: away },
      ]);
      assert.equal(result.states[3]?.currentLevel, "HIGH");
      assert.notEqual(result.states[4]?.currentLevel, "HIGH");
      return result;
    },
  },
  {
    name: "threshold oscillation: calibration replay does not spam",
    verify: () => {
      const result = replay(
        Array.from({ length: 30 }, (_, seconds) => ({
          seconds,
          score: seconds % 2 ? 66 : 64,
          level: seconds % 2 ? "WARNING" : "WATCH",
        })),
      );
      assert.equal(result.notifications, 0);
      return result;
    },
  },
  {
    name: "stale track: no escalation",
    verify: () => {
      const result = replay([
        { seconds: 0, patch: { status: "stale" } },
        { seconds: 1, patch: { status: "stale" } },
      ]);
      assert(result.states.every((s) => s.currentLevel === "INFO"));
      assert.equal(result.notifications, 0);
      return result;
    },
  },
  {
    name: "high uncertainty: evidence does not grow, HIGH is blocked",
    verify: () => {
      const result = replay([
        { seconds: 0, patch: { uncertaintyKm: 100 } },
        { seconds: 1, patch: { uncertaintyKm: 100 } },
      ]);
      assert(
        result.assessments.every(
          (a) =>
            a.level !== "HIGH" &&
            a.explanationCodes.includes("UNCERTAINTY_DOMINATES"),
        ),
      );
      return result;
    },
  },
  {
    name: "disappeared and reappeared track: resolution grace and new evidence",
    verify: () => {
      const resolved = {
        status: "resolved",
        updatedAt: new Date(epoch + 2000).toISOString(),
        confirmedAt: new Date(epoch + 2000).toISOString(),
      };
      const result = replay([
        { seconds: 0 },
        { seconds: 1 },
        { seconds: 2, patch: resolved },
        { seconds: 63, patch: resolved, eventKey: "resolution-aging-tick" },
        { seconds: 70 },
        { seconds: 71 },
      ]);
      assert.equal(result.states[3]?.currentLevel, "RESOLVED");
      assert.equal(result.states[4]?.currentLevel, "INFO");
      assert.equal(result.states[5]?.currentLevel, "HIGH");
      assert.equal(result.notifications, 3);
      return result;
    },
  },
  {
    name: "duplicate upstream event: one notification per change",
    verify: () => {
      const result = replay([
        { seconds: 0, eventKey: "a" },
        { seconds: 0, eventKey: "a" },
        { seconds: 1, eventKey: "b" },
        { seconds: 1, eventKey: "b" },
      ]);
      assert.equal(result.notifications, 1);
      assert.deepEqual(result.states[2], result.states[3]);
      return result;
    },
  },
  {
    name: "areaOnly: no personalized geometry",
    verify: () => {
      const result = replay([
        { seconds: 0, patch: { areaOnly: true } },
        { seconds: 1, patch: { areaOnly: true } },
      ]);
      assert(
        result.assessments.every(
          (a) => a.level === "INFO" && Object.keys(a.geometry).length === 1,
        ),
      );
      assert.equal(result.notifications, 0);
      return result;
    },
  },
  {
    name: "advisory: contextual information only",
    verify: () => {
      const result = replay([
        { seconds: 0, patch: { advisory: true } },
        { seconds: 1, patch: { advisory: true } },
      ]);
      assert(result.states.every((s) => s.currentLevel === "INFO"));
      assert.equal(result.notifications, 0);
      return result;
    },
  },
  {
    name: "official alert begins/ends: never creates movement evidence",
    verify: () => {
      const result = replay([
        { seconds: 0, official: false, patch: { velocity: undefined } },
        { seconds: 1, official: true, patch: { velocity: undefined } },
        { seconds: 2, official: false, patch: { velocity: undefined } },
      ]);
      assert(
        result.assessments.every(
          (a) => a.factors.approaching === 0 && !a.geometry.corridorIntersects,
        ),
      );
      assert.equal(result.notifications, 0);
      return result;
    },
  },
  {
    name: "two crossing tracks: independent identity and state",
    verify: () => {
      const result = replay([
        { seconds: 0, patch: { id: "synthetic-a" } },
        { seconds: 1, patch: { id: "synthetic-a" } },
      ]);
      const second = replay([
        {
          seconds: 0,
          patch: {
            id: "synthetic-b",
            lat: 0.5,
            lon: 0,
            velocity: { bearingDeg: 90, speedKmh: 150 },
          },
        },
        {
          seconds: 1,
          patch: {
            id: "synthetic-b",
            lat: 0.5,
            lon: 0,
            velocity: { bearingDeg: 90, speedKmh: 150 },
          },
        },
      ]);
      assert.notEqual(
        result.assessments[0]?.trackId,
        second.assessments[0]?.trackId,
      );
      assert.equal(second.notifications, 0);
      return result;
    },
  },
];

for (const scenario of scenarios) {
  const result = scenario.verify();
  console.log(
    JSON.stringify({
      scenario: scenario.name,
      passed: true,
      evaluations: result.assessments.length,
      notifications: result.notifications,
      levels: [...new Set(result.states.map((s) => s.currentLevel))],
    }),
  );
}
console.log(
  JSON.stringify({
    simulation: "synthetic-only",
    scenariosPassed: scenarios.length,
    guarantees: false,
  }),
);
