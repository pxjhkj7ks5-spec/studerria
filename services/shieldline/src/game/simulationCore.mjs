import { createLaunchSectorState, launchSectorCategory, pickWeightedSector, randomPointInSector } from "./launchSystem.mjs";

export const SIM_VERSION = "2.2.0";
// Geography changes must not silently rebalance established mission outcomes.
const OUTCOME_RANDOM_VERSION = "2.1.0";

const targetSectorCoordinates = {
  north: { lat: 52.0, lng: 31.5 },
  south: { lat: 45.6, lng: 32.4 },
  east: { lat: 50.1, lng: 37.4 },
  west: { lat: 49.2, lng: 23.8 },
  hq: { lat: 50.45, lng: 30.52 },
};

const sectorPoints = {
  north: { x: 50, y: 20 },
  south: { x: 50, y: 80 },
  east: { x: 80, y: 50 },
  west: { x: 20, y: 50 },
  hq: { x: 50, y: 50 },
};

export function stableHash(value) {
  let hash = 2166136261;
  for (let index = 0; index < String(value).length; index += 1) hash = Math.imul(hash ^ String(value).charCodeAt(index), 16777619);
  return (hash >>> 0).toString(36);
}

function seededRandom(seed) {
  let state = 2166136261;
  for (let index = 0; index < seed.length; index += 1) state = Math.imul(state ^ seed.charCodeAt(index), 16777619);
  return () => {
    state += 0x6d2b79f5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

export function calculateDefenseBonus(plan = {}) {
  const assets = Array.isArray(plan.assets) ? plan.assets : [];
  const assetCount = Number.isFinite(Number(plan.assetCount)) ? Number(plan.assetCount) : assets.length;
  const radarCount = Number.isFinite(Number(plan.radarCount)) ? Number(plan.radarCount) : assets.filter((asset) => asset?.kind === "radar").length;
  const kineticCount = Number.isFinite(Number(plan.kineticCount)) ? Number(plan.kineticCount) : assets.filter((asset) => !["radar", "ew"].includes(asset?.kind)).length;
  const averageReadiness = Number.isFinite(Number(plan.averageReadiness))
    ? Number(plan.averageReadiness)
    : assetCount ? assets.reduce((sum, asset) => sum + Math.max(0, Math.min(100, Number(asset?.readiness || 0))), 0) / assetCount : 0;
  return Math.min(0.24, assetCount * 0.012 + radarCount * 0.018 + kineticCount * 0.02 + (averageReadiness / 100) * 0.04);
}

function event(runId, sequence, type, occurredAtMs, message, extras = {}) {
  return {
    id: `${runId}-evt-${sequence}`,
    runId,
    sequence,
    tick: occurredAtMs,
    type,
    occurredAtMs,
    simVersion: SIM_VERSION,
    schemaVersion: 1,
    message,
    payload: {},
    ...extras,
  };
}

function replayEvent(entry, route, interceptPoint) {
  return {
    ...entry,
    replayAtMs: entry.occurredAtMs,
    ...(route ? { route } : {}),
    ...(interceptPoint ? { interceptPoint } : {}),
  };
}

function addSnapshot(snapshots, runId, entry, state) {
  snapshots.push({ runId, sequence: entry.sequence, tick: entry.tick, simVersion: SIM_VERSION, state: { ...state, lastSequence: entry.sequence } });
}

function buildSnapshots(runId, events) {
  const snapshots = [];
  const state = { interceptions: 0, impacts: 0, ammoSpent: 0, status: "running", result: "pending" };
  for (const entry of events) {
    if (entry.type === "interception") state.interceptions += Number(entry.payload.count || 0);
    if (entry.type === "impact") state.impacts += Number(entry.payload.count || 0);
    if (entry.type === "battery.fired") state.ammoSpent += Number(entry.payload.ammoSpent || entry.payload.count || 0);
    if (entry.type === "mission.completed") {
      state.status = "completed";
      state.result = String(entry.payload.result || "contained");
    }
    if (entry.sequence === 1 || entry.sequence % 200 === 0 || entry === events.at(-1)) addSnapshot(snapshots, runId, entry, state);
  }
  return snapshots;
}

function completedAt(startedAt, elapsedMs) {
  const start = Date.parse(startedAt);
  return Number.isFinite(start) ? new Date(start + elapsedMs).toISOString() : startedAt;
}

/** Pure rules engine shared byte-for-byte by browser offline mode and the server. */
export function simulateOperation({ mission, seed, plan = {}, defenseBonus, startedAt = "2026-07-09T00:00:00.000Z" }) {
  if (!mission?.id || !Array.isArray(mission.waves)) throw new Error("A versioned mission definition is required.");
  const normalizedSeed = String(seed || "campaign-seed");
  const random = seededRandom(`${OUTCOME_RANDOM_VERSION}:${mission.id}:${normalizedSeed}`);
  const launchRandom = seededRandom(`${SIM_VERSION}:${mission.id}:${normalizedSeed}:launch-sectors`);
  const missionLaunchSectors = createLaunchSectorState(mission.launchSectorIds);
  const safeSeed = normalizedSeed.slice(0, 18).replace(/[^a-z0-9-]/gi, "-") || "seed";
  const runId = `run-${mission.id}-${safeSeed}-${stableHash(normalizedSeed)}`;
  const events = [];
  const replay = [];
  const effectiveDefenseBonus = Number.isFinite(Number(defenseBonus)) ? Number(defenseBonus) : calculateDefenseBonus(plan);
  let sequence = 1;
  let interceptions = 0;
  let impacts = 0;
  let ammoSpent = 0;

  events.push(event(runId, sequence++, "mission.started", 0, "Mission command accepted; authoritative simulation started.", {
    payload: { missionId: mission.id, seed: normalizedSeed, simVersion: SIM_VERSION },
  }));

  for (const wave of mission.waves) {
    const detectedAt = Math.max(500, Number(wave.etaSeconds || 0) * 500);
    const launchSector = pickWeightedSector(missionLaunchSectors, wave.threatKind, launchRandom);
    const origin = randomPointInSector(launchSector, launchRandom);
    const target = targetSectorCoordinates[wave.targetSector] || targetSectorCoordinates.hq;
    const route = { from: wave.originSector, to: wave.targetSector };
    const commonPayload = {
      tracks: wave.size,
      threatKind: wave.threatKind,
      originLat: origin.lat,
      originLng: origin.lng,
      targetLat: target.lat,
      targetLng: target.lng,
      launchSectorId: launchSector.id,
      launchSectorName: launchSector.name,
      launchSectorLat: launchSector.lat,
      launchSectorLng: launchSector.lng,
      launchSectorRadiusKm: launchSector.radiusKm,
      launchSectorCategory: launchSectorCategory(launchSector),
    };
    const warning = event(runId, sequence++, "launch.warning", Math.max(0, detectedAt - 2_000), `${launchSector.name} entered warning state.`, {
      sectorId: launchSector.id,
      waveId: wave.id,
      targetId: wave.targetSector,
      payload: commonPayload,
    });
    const launched = event(runId, sequence++, "threat.launched", Math.max(0, detectedAt - 1_000), `${wave.size} ${wave.threatKind} track${wave.size === 1 ? "" : "s"} launched.`, {
      sectorId: launchSector.id,
      waveId: wave.id,
      targetId: wave.targetSector,
      payload: commonPayload,
    });
    const detected = event(runId, sequence++, "track.detected", detectedAt, `${wave.size} tracks detected toward the ${wave.targetSector} sector.`, {
      sectorId: wave.targetSector,
      waveId: wave.id,
      targetId: wave.id,
      payload: { ...commonPayload, difficulty: wave.difficulty },
    });
    events.push(warning, launched, detected);
    replay.push(replayEvent(warning, route), replayEvent(launched, route), replayEvent(detected, route));

    const coverage = Math.min(0.9, 0.38 + random() * 0.42 + effectiveDefenseBonus);
    const successful = Math.max(0, Math.min(wave.size, Math.round(wave.size * coverage - wave.difficulty / 140 + random() * 1.8)));
    const missed = wave.size - successful;
    interceptions += successful;
    impacts += missed;
    const waveAmmo = successful * (wave.threatKind === "kh101" ? 3 : 1);
    ammoSpent += waveAmmo;

    if (successful) {
      const fired = event(runId, sequence++, "battery.fired", detectedAt + 450, `Sector defense fired on ${successful} confirmed track${successful === 1 ? "" : "s"}.`, {
        sectorId: wave.targetSector,
        waveId: wave.id,
        assetId: "sector-defense",
        targetId: wave.id,
        payload: { ...commonPayload, count: successful, ammoSpent: waveAmmo },
      });
      const fromPoint = sectorPoints[wave.originSector] || sectorPoints.east;
      const toPoint = sectorPoints[wave.targetSector] || sectorPoints.hq;
      const interceptPoint = {
        x: (fromPoint.x + toPoint.x) / 2 + (random() - 0.5) * 14,
        y: (fromPoint.y + toPoint.y) / 2 + (random() - 0.5) * 14,
      };
      const interceptLat = (origin.lat + target.lat) / 2 + (random() - 0.5) * 1.2;
      const interceptLng = (origin.lng + target.lng) / 2 + (random() - 0.5) * 1.2;
      const intercepted = event(runId, sequence++, "interception", detectedAt + 900, `${successful} track${successful === 1 ? "" : "s"} intercepted over ${wave.targetSector}.`, {
        sectorId: wave.targetSector,
        waveId: wave.id,
        assetId: "sector-defense",
        targetId: wave.id,
        payload: { ...commonPayload, count: successful, latitude: interceptLat, longitude: interceptLng },
      });
      events.push(fired, intercepted);
      replay.push(replayEvent(fired, { from: wave.targetSector, to: wave.targetSector }), replayEvent(intercepted, route, interceptPoint));
    }

    if (missed) {
      const impact = event(runId, sequence++, "impact", detectedAt + 1_700, `${missed} track${missed === 1 ? "" : "s"} reached the ${wave.targetSector} sector.`, {
        sectorId: wave.targetSector,
        waveId: wave.id,
        targetId: wave.targetSector,
        payload: { ...commonPayload, count: missed, latitude: target.lat, longitude: target.lng },
      });
      events.push(impact);
      replay.push(replayEvent(impact, route));
    }
  }

  const result = impacts === 0 ? "victory" : impacts <= 5 ? "contained" : "setback";
  const completedAtMs = Math.max(7_600, ...events.map((entry) => entry.occurredAtMs)) + 500;
  events.push(event(runId, sequence, "mission.completed", completedAtMs, result === "victory" ? "Mission complete: all critical tracks contained." : "Mission complete: command report is ready.", {
    payload: { result, interceptions, impacts, ammoSpent },
  }));

  return {
    id: runId,
    missionId: mission.id,
    seed: normalizedSeed,
    startedAt,
    completedAt: completedAt(startedAt, completedAtMs),
    events,
    replay,
    snapshots: buildSnapshots(runId, events),
    simVersion: SIM_VERSION,
    revision: 1,
    status: "completed",
    result,
    interceptions,
    impacts,
    ammoSpent,
    sectorSummary: {
      north: { coverage: 72, pressure: 32, damage: 0 },
      south: { coverage: 61, pressure: 44, damage: Math.max(0, impacts - 2) * 3 },
      east: { coverage: 68, pressure: 70, damage: impacts * 4 },
      west: { coverage: 74, pressure: 36, damage: 0 },
    },
  };
}
