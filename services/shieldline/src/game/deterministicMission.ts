import type { MissionDefinition, MissionRun, ReplayEvent, SectorId, SimulationEvent } from "../domain/contracts";

const sectorPoints: Record<SectorId, { x: number; y: number }> = {
  north: { x: 50, y: 20 }, south: { x: 50, y: 80 }, east: { x: 80, y: 50 }, west: { x: 20, y: 50 }, hq: { x: 50, y: 50 },
};

function seededRandom(seed: string) {
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

function event(runId: string, sequence: number, type: SimulationEvent["type"], occurredAtMs: number, message: string, data: Omit<SimulationEvent, "id" | "runId" | "sequence" | "type" | "occurredAtMs" | "message" | "payload"> & { payload?: SimulationEvent["payload"] } = {}): SimulationEvent {
  return { id: `${runId}-evt-${sequence}`, runId, sequence, type, occurredAtMs, message, payload: data.payload || {}, sectorId: data.sectorId, waveId: data.waveId, assetId: data.assetId };
}

/** Pure deterministic core: same mission, seed and version always yield the same run. */
export function runDeterministicMission(mission: MissionDefinition, seed: string): MissionRun {
  const random = seededRandom(`${mission.id}:${seed}:v1`);
  const runId = `run-${mission.id}-${seed.slice(0, 8)}`;
  const events: SimulationEvent[] = [];
  const replay: ReplayEvent[] = [];
  let sequence = 1;
  let interceptions = 0;
  let impacts = 0;
  let ammoSpent = 0;
  events.push(event(runId, sequence++, "mission.started", 0, "Mission command accepted; deterministic simulation started.", { payload: { seed } }));

  for (const wave of mission.waves) {
    const detectedAt = Math.max(500, wave.etaSeconds * 500);
    const detected = event(runId, sequence++, "wave.detected", detectedAt, `${wave.size} tracks detected toward the ${wave.targetSector} sector.`, { sectorId: wave.targetSector, waveId: wave.id, payload: { tracks: wave.size, difficulty: wave.difficulty } });
    events.push(detected);
    replay.push({ ...detected, replayAtMs: detectedAt, route: { from: wave.originSector, to: wave.targetSector } });
    const coverage = 0.38 + random() * 0.42;
    const successCount = Math.max(0, Math.min(wave.size, Math.round(wave.size * coverage - wave.difficulty / 140 + random() * 1.8)));
    const misses = wave.size - successCount;
    interceptions += successCount;
    ammoSpent += successCount * (wave.threatKind === "kh101" ? 3 : 1);
    if (successCount) {
      const interceptionAt = detectedAt + 900;
      const intercept = event(runId, sequence++, "interception", interceptionAt, `${successCount} track${successCount === 1 ? "" : "s"} intercepted over ${wave.targetSector}.`, { sectorId: wave.targetSector, waveId: wave.id, assetId: "sector-defense", payload: { count: successCount } });
      events.push(intercept);
      const from = sectorPoints[wave.originSector]; const to = sectorPoints[wave.targetSector];
      replay.push({ ...intercept, replayAtMs: interceptionAt, route: { from: wave.originSector, to: wave.targetSector }, interceptPoint: { x: (from.x + to.x) / 2 + (random() - .5) * 14, y: (from.y + to.y) / 2 + (random() - .5) * 14 } });
    }
    if (misses) {
      impacts += misses;
      const impactAt = detectedAt + 1700;
      const impact = event(runId, sequence++, "impact", impactAt, `${misses} track${misses === 1 ? "" : "s"} reached the ${wave.targetSector} sector.`, { sectorId: wave.targetSector, waveId: wave.id, payload: { count: misses } });
      events.push(impact);
      replay.push({ ...impact, replayAtMs: impactAt, route: { from: wave.originSector, to: wave.targetSector } });
    }
  }
  const result: MissionRun["result"] = impacts === 0 ? "victory" : impacts <= 5 ? "contained" : "setback";
  const completedAtMs = mission.waves.length * 1800 + 2200;
  events.push(event(runId, sequence++, "mission.completed", completedAtMs, result === "victory" ? "Mission complete: all critical tracks contained." : "Mission complete: command report is ready.", { payload: { result, interceptions, impacts } }));
  return {
    id: runId, missionId: mission.id, seed, startedAt: "2026-07-09T00:00:00.000Z", completedAt: "2026-07-09T00:45:00.000Z", events, replay, result, interceptions, impacts, ammoSpent,
    sectorSummary: {
      north: { coverage: 72, pressure: 32, damage: 0 }, south: { coverage: 61, pressure: 44, damage: Math.max(0, impacts - 2) * 3 }, east: { coverage: 68, pressure: 70, damage: impacts * 4 }, west: { coverage: 74, pressure: 36, damage: 0 },
    },
  };
}
