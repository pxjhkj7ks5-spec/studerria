import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";

const DEFAULT_STORE = { version: 1, events: [], runs: {}, dailyReports: {}, rankedSubmissions: {}, rooms: {}, notificationOutbox: [] };
const mission = {
  id: "campaign-night-01",
  title: "Night 01: Signal Window",
  waves: [
    { id: "wave-01", originSector: "east", targetSector: "east", etaSeconds: 28, size: 8, difficulty: 42, threatKind: "geran2" },
    { id: "wave-02", originSector: "north", targetSector: "north", etaSeconds: 52, size: 3, difficulty: 62, threatKind: "kh101" },
    { id: "wave-03", originSector: "south", targetSector: "west", etaSeconds: 75, size: 6, difficulty: 48, threatKind: "gerbera" },
  ],
};

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

function event(runId, sequence, type, occurredAtMs, message, extras = {}) {
  return { id: `${runId}-evt-${sequence}`, runId, sequence, type, occurredAtMs, message, payload: {}, ...extras };
}

function stableHash(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) hash = Math.imul(hash ^ value.charCodeAt(index), 16777619);
  return (hash >>> 0).toString(36);
}

export function simulateMission(seed, now = new Date().toISOString(), defenseBonus = 0) {
  const random = seededRandom(`${mission.id}:${seed}:v1`);
  const runId = `run-${mission.id}-${seed.slice(0, 18).replace(/[^a-z0-9-]/gi, "-")}-${stableHash(seed)}`;
  const events = [event(runId, 1, "mission.started", 0, "Mission command accepted; authoritative simulation started.", { payload: { seed } })];
  const replay = [];
  let sequence = 2;
  let interceptions = 0;
  let impacts = 0;
  let ammoSpent = 0;

  for (const wave of mission.waves) {
    const detectedAt = Math.max(500, wave.etaSeconds * 500);
    const detected = event(runId, sequence++, "wave.detected", detectedAt, `${wave.size} tracks detected toward the ${wave.targetSector} sector.`, { sectorId: wave.targetSector, waveId: wave.id, payload: { tracks: wave.size, difficulty: wave.difficulty } });
    events.push(detected); replay.push({ ...detected, replayAtMs: detectedAt, route: { from: wave.originSector, to: wave.targetSector } });
    const coverage = Math.min(0.9, 0.38 + random() * 0.42 + defenseBonus);
    const success = Math.max(0, Math.min(wave.size, Math.round(wave.size * coverage - wave.difficulty / 140 + random() * 1.8)));
    const missed = wave.size - success;
    interceptions += success; impacts += missed; ammoSpent += success * (wave.threatKind === "kh101" ? 3 : 1);
    if (success) {
      const interceptionAt = detectedAt + 900;
      const intercept = event(runId, sequence++, "interception", interceptionAt, `${success} track${success === 1 ? "" : "s"} intercepted over ${wave.targetSector}.`, { sectorId: wave.targetSector, waveId: wave.id, assetId: "sector-defense", payload: { count: success } });
      events.push(intercept); replay.push({ ...intercept, replayAtMs: interceptionAt, route: { from: wave.originSector, to: wave.targetSector }, interceptPoint: { x: 45 + (random() - .5) * 22, y: 50 + (random() - .5) * 22 } });
    }
    if (missed) {
      const impactAt = detectedAt + 1700;
      const impact = event(runId, sequence++, "impact", impactAt, `${missed} track${missed === 1 ? "" : "s"} reached the ${wave.targetSector} sector.`, { sectorId: wave.targetSector, waveId: wave.id, payload: { count: missed } });
      events.push(impact); replay.push({ ...impact, replayAtMs: impactAt, route: { from: wave.originSector, to: wave.targetSector } });
    }
  }
  const result = impacts === 0 ? "victory" : impacts <= 5 ? "contained" : "setback";
  events.push(event(runId, sequence, "mission.completed", 7600, result === "victory" ? "Mission complete: all critical tracks contained." : "Mission complete: command report is ready.", { payload: { result, interceptions, impacts } }));
  return { id: runId, missionId: mission.id, seed, startedAt: now, completedAt: now, events, replay, result, interceptions, impacts, ammoSpent, sectorSummary: { north: { coverage: 72, pressure: 32, damage: 0 }, south: { coverage: 61, pressure: 44, damage: Math.max(0, impacts - 2) * 3 }, east: { coverage: 68, pressure: 70, damage: impacts * 4 }, west: { coverage: 74, pressure: 36, damage: 0 } } };
}

export function dayKey(now = new Date()) { return now.toISOString().slice(0, 10); }

function normalizeDailyPlan(input = {}) {
  const assets = Array.isArray(input.assets) ? input.assets.slice(0, 32).map((asset) => ({
    kind: String(asset?.kind || "unknown").slice(0, 32),
    cityId: String(asset?.cityId || "unknown").slice(0, 48),
    readiness: Math.max(0, Math.min(100, Number(asset?.readiness || 0))),
  })) : [];
  const assetCount = assets.length;
  const radarCount = assets.filter((asset) => asset.kind === "radar").length;
  const kineticCount = assets.filter((asset) => !["radar", "ew"].includes(asset.kind)).length;
  const averageReadiness = assetCount ? assets.reduce((sum, asset) => sum + asset.readiness, 0) / assetCount : 0;
  return { assetCount, radarCount, kineticCount, averageReadiness, assets };
}

function coOpSectorForCity(cityId) {
  if (["chernihiv", "sumy", "kyiv", "zhytomyr", "rivne", "lutsk"].includes(cityId)) return "north";
  if (["kharkiv", "dnipro", "zaporizhzhia", "poltava", "kryvyi-rih"].includes(cityId)) return "east";
  if (["odesa", "mykolaiv", "kropyvnytskyi", "cherkasy"].includes(cityId)) return "south";
  return "west";
}

export async function createGameStore(file) {
  async function readStore() {
    if (!existsSync(file)) return structuredClone(DEFAULT_STORE);
    try { return { ...structuredClone(DEFAULT_STORE), ...JSON.parse(await readFile(file, "utf8")) }; } catch { return structuredClone(DEFAULT_STORE); }
  }
  async function save(store) {
    await mkdir(dirname(file), { recursive: true });
    const temp = `${file}.tmp`;
    await writeFile(temp, `${JSON.stringify(store, null, 2)}\n`, "utf8");
    await rename(temp, file);
  }
  async function persistRun(run, metadata = {}) {
    const store = await readStore();
    if (!store.runs[run.id]) {
      store.runs[run.id] = { ...run, metadata };
      store.events.push(...run.events);
      await save(store);
    }
    return store.runs[run.id];
  }
  return {
    async runMission(seed, actorId = "web-commander") { return persistRun(simulateMission(seed), { source: "command", actorId, displayName: actorId === "web-commander" ? "Web Commander" : actorId }); },
    async getRun(runId) { return (await readStore()).runs[runId] || null; },
    async getDailyReport(key = dayKey(), plan = {}) {
      const store = await readStore();
      if (store.dailyReports[key]) return { report: store.dailyReports[key], run: store.runs[store.dailyReports[key].runId] };
      const resolvedPlan = normalizeDailyPlan(plan);
      if (!resolvedPlan.assetCount) throw new Error("Deploy at least one defense asset before resolving the daily attack.");
      const defenseBonus = Math.min(0.24, resolvedPlan.assetCount * 0.012 + resolvedPlan.radarCount * 0.018 + resolvedPlan.kineticCount * 0.02 + (resolvedPlan.averageReadiness / 100) * 0.04);
      const run = simulateMission(`daily-${key}-assets-${resolvedPlan.assetCount}-radar-${resolvedPlan.radarCount}-kinetic-${resolvedPlan.kineticCount}`, new Date().toISOString(), defenseBonus);
      store.runs[run.id] = { ...run, metadata: { source: "daily", dayKey: key, plan: resolvedPlan, defenseBonus } };
      store.events.push(...run.events);
      const report = { id: `daily-${key}`, cityId: "city-01", dayKey: key, runId: run.id, summary: `${run.interceptions} interceptions, ${run.impacts} impacts from ${resolvedPlan.assetCount} prepared defense asset(s).`, replayId: run.id, recommendedAction: run.impacts ? "Reinforce the east sector before the next night." : "Use the stable night to recover readiness." };
      store.dailyReports[key] = report;
      store.notificationOutbox.push({ id: `notice-${key}`, type: "daily.report.ready", createdAt: new Date().toISOString(), payload: { dayKey: key, reportId: report.id } });
      await save(store);
      return { report, run: store.runs[run.id] };
    },
    async leaderboard() {
      const store = await readStore();
      return Object.values(store.runs).filter((run) => run.metadata?.source === "ranked").map((run) => ({ userId: run.metadata?.actorId || "anonymous", displayName: run.metadata?.displayName || "Commander", score: Math.max(0, run.interceptions * 100 - run.impacts * 35 - run.ammoSpent), result: run.result, updatedAt: run.completedAt })).sort((left, right) => right.score - left.score).slice(0, 100).map((entry, index) => ({ ...entry, rank: index + 1 }));
    },
    rankedChallenge(key = dayKey()) {
      return { id: `ranked-${key}`, dayKey: key, seed: `ranked-${key}-v1`, title: "Daily Equal Command", rules: ["Same seed for every commander.", "Server resolves the submitted defense plan.", "No paid combat modifiers."] };
    },
    async submitRanked(challengeId, plan, actorId) {
      const challenge = this.rankedChallenge(challengeId.replace(/^ranked-/, ""));
      if (challenge.id !== challengeId) throw new Error("Unknown ranked challenge.");
      const store = await readStore();
      const existingRunId = store.rankedSubmissions[challenge.id]?.[actorId];
      if (existingRunId) {
        const run = store.runs[existingRunId];
        const entries = await this.leaderboard();
        return { challengeId, challenge, run, entry: entries.find((entry) => entry.userId === actorId) || { rank: entries.length + 1, userId: actorId, displayName: actorId, score: 0, result: run.result, updatedAt: run.completedAt } };
      }
      const resolvedPlan = normalizeDailyPlan(plan);
      if (!resolvedPlan.assetCount) throw new Error("Deploy at least one defense asset before entering Ranked Challenge.");
      const defenseBonus = Math.min(0.24, resolvedPlan.assetCount * 0.012 + resolvedPlan.radarCount * 0.018 + resolvedPlan.kineticCount * 0.02 + (resolvedPlan.averageReadiness / 100) * 0.04);
      const run = simulateMission(`${challenge.seed}-${actorId}`, new Date().toISOString(), defenseBonus);
      store.runs[run.id] = { ...run, metadata: { source: "ranked", challengeId, actorId, displayName: actorId, plan: resolvedPlan, defenseBonus } };
      store.events.push(...run.events);
      store.rankedSubmissions[challenge.id] = { ...(store.rankedSubmissions[challenge.id] || {}), [actorId]: run.id };
      await save(store);
      const entries = await this.leaderboard();
      return { challengeId, challenge, run: store.runs[run.id], entry: entries.find((entry) => entry.userId === actorId) };
    },
    async getRoom(roomId = "kyiv-01") {
      const store = await readStore();
      if (!store.rooms[roomId]) {
        store.rooms[roomId] = { id: roomId, mode: "async", cityId: "city-01", revision: 1, sectorAssignments: { hq: "hq" }, members: [{ userId: "hq", role: "hq", ready: true }], commandLog: [] };
        await save(store);
      }
      return store.rooms[roomId];
    },
    async claimSector(roomId, sectorId, actorId) {
      const store = await readStore();
      const room = store.rooms[roomId] || await this.getRoom(roomId);
      if (room.sectorAssignments[sectorId] && room.sectorAssignments[sectorId] !== actorId) throw new Error("Sector is already assigned.");
      const sequence = room.commandLog.length + 1;
      const command = event(`room-${roomId}`, sequence, "mission.started", Date.now(), `${actorId} claimed ${sectorId}.`, { sectorId, payload: { command: "sector.claim", actorId } });
      room.sectorAssignments[sectorId] = actorId;
      room.members = room.members.filter((member) => member.userId !== actorId).concat({ userId: actorId, role: sectorId, ready: true });
      room.commandLog.push(command); room.revision += 1; store.rooms[roomId] = room; store.events.push(command); await save(store);
      return room;
    },
    async appendRoomCommand(roomId, actorId, sectorId, type, payload = {}) {
      const store = await readStore();
      const room = store.rooms[roomId];
      if (!room) throw new Error("Co-op room not found.");
      const member = room.members.find((item) => item.userId === actorId);
      if (!member || member.role !== sectorId) throw new Error("Claim this sector before issuing a command.");
      if (type === "asset.place" && coOpSectorForCity(String(payload.cityId || "")) !== sectorId) throw new Error("This asset is outside your assigned sector.");
      const sequence = room.commandLog.length + 1;
      const command = event(`room-${roomId}`, sequence, "mission.started", Date.now(), `${actorId} issued ${type} in ${sectorId}.`, { sectorId, payload: { command: type, actorId, ...payload } });
      room.commandLog.push(command); room.revision += 1; store.rooms[roomId] = room; store.events.push(command); await save(store);
      return room;
    },
    async notificationOutbox() { return (await readStore()).notificationOutbox; },
  };
}
