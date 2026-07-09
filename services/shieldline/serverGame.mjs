import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";

const DEFAULT_STORE = { version: 2, events: [], runs: {}, dailyReports: {}, dailyCities: {}, campaigns: {}, rankedSubmissions: {}, rooms: {}, notificationOutbox: [], notificationPreferences: {} };
const VALID_ASSET_KINDS = new Set(["radar", "mvg", "boat", "ew", "manpads", "gepard", "buk", "s300", "iris-t", "nasams", "patriot", "drone-operators"]);
const missions = [
  {
    id: "campaign-night-01",
    title: "Night 01: Signal Window",
    waves: [
    { id: "wave-01", originSector: "east", targetSector: "east", etaSeconds: 28, size: 8, difficulty: 42, threatKind: "geran2" },
    { id: "wave-02", originSector: "north", targetSector: "north", etaSeconds: 52, size: 3, difficulty: 62, threatKind: "kh101" },
    { id: "wave-03", originSector: "south", targetSector: "west", etaSeconds: 75, size: 6, difficulty: 48, threatKind: "gerbera" },
  ],
  },
  {
    id: "campaign-night-02",
    title: "Night 02: Blackout Relay",
    waves: [
      { id: "wave-01", originSector: "south", targetSector: "south", etaSeconds: 24, size: 10, difficulty: 48, threatKind: "geran2" },
      { id: "wave-02", originSector: "east", targetSector: "east", etaSeconds: 50, size: 5, difficulty: 67, threatKind: "kalibr" },
      { id: "wave-03", originSector: "north", targetSector: "east", etaSeconds: 79, size: 4, difficulty: 72, threatKind: "kh101" },
    ],
  },
  {
    id: "campaign-night-03",
    title: "Night 03: Last Reserve",
    waves: [
      { id: "wave-01", originSector: "east", targetSector: "east", etaSeconds: 20, size: 12, difficulty: 58, threatKind: "gerbera" },
      { id: "wave-02", originSector: "south", targetSector: "west", etaSeconds: 47, size: 6, difficulty: 78, threatKind: "kalibr" },
      { id: "wave-03", originSector: "north", targetSector: "north", etaSeconds: 74, size: 5, difficulty: 84, threatKind: "kh101" },
    ],
  },
];

function missionById(missionId) {
  return missions.find((entry) => entry.id === missionId) || missions[0];
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

function event(runId, sequence, type, occurredAtMs, message, extras = {}) {
  return { id: `${runId}-evt-${sequence}`, runId, sequence, type, occurredAtMs, message, payload: {}, ...extras };
}

function stableHash(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) hash = Math.imul(hash ^ value.charCodeAt(index), 16777619);
  return (hash >>> 0).toString(36);
}

export function simulateMission(seed, now = new Date().toISOString(), defenseBonus = 0, missionId = missions[0].id) {
  const mission = missionById(missionId);
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
    position: Number.isFinite(Number(asset?.position?.lat)) && Number.isFinite(Number(asset?.position?.lng)) ? { lat: Number(asset.position.lat), lng: Number(asset.position.lng) } : undefined,
  })).filter((asset) => VALID_ASSET_KINDS.has(asset.kind)) : [];
  const assetCount = assets.length;
  const radarCount = assets.filter((asset) => asset.kind === "radar").length;
  const kineticCount = assets.filter((asset) => !["radar", "ew"].includes(asset.kind)).length;
  const averageReadiness = assetCount ? assets.reduce((sum, asset) => sum + asset.readiness, 0) / assetCount : 0;
  return { assetCount, radarCount, kineticCount, averageReadiness, assets };
}

function defenseBonusFor(plan) {
  return Math.min(0.24, plan.assetCount * 0.012 + plan.radarCount * 0.018 + plan.kineticCount * 0.02 + (plan.averageReadiness / 100) * 0.04);
}

function emptyDailyCity(actorId) {
  return { id: `city-${stableHash(actorId)}`, ownerId: actorId, revision: 1, morale: 76, energy: 78, infrastructure: 84, damage: 0, assets: [], lastResolvedDay: null, updatedAt: new Date().toISOString() };
}

function dailyReportKey(actorId, key) {
  return `${actorId}:${key}`;
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
    async runMission(seed, actorId = "web-commander", plan = {}, missionId = missions[0].id, source = "campaign") {
      const resolvedPlan = normalizeDailyPlan(plan);
      if (!resolvedPlan.assetCount) throw new Error("Deploy at least one defense asset before resolving the operation.");
      const defenseBonus = defenseBonusFor(resolvedPlan);
      const mission = missionById(missionId);
      const run = await persistRun(simulateMission(seed, new Date().toISOString(), defenseBonus, mission.id), { source, actorId, displayName: actorId === "web-commander" ? "Web Commander" : actorId, plan: resolvedPlan, defenseBonus });
      if (source === "campaign") {
        const store = await readStore();
        const current = store.campaigns[actorId] || { currentMissionId: missions[0].id, completedMissionIds: [], lastRunId: null };
        if (current.currentMissionId === mission.id && run.result !== "setback") {
          current.completedMissionIds = [...new Set([...current.completedMissionIds, mission.id])];
          current.currentMissionId = missions[missions.findIndex((entry) => entry.id === mission.id) + 1]?.id || null;
        }
        current.lastRunId = run.id;
        store.campaigns[actorId] = current;
        store.events.push(event(`campaign-${actorId}`, store.events.length + 1, "mission.completed", Date.now(), `${actorId} resolved ${mission.id}.`, { payload: { runId: run.id, result: run.result } }));
        await save(store);
      }
      return run;
    },
    async recordCampaignCommand(actorId, type, payload = {}) {
      const store = await readStore();
      const command = event(`campaign-${actorId}`, store.events.length + 1, "mission.started", Date.now(), `${actorId} issued ${type}.`, { payload: { command: type, actorId, ...payload } });
      store.events.push(command);
      await save(store);
    },
    async getRun(runId) { return (await readStore()).runs[runId] || null; },
    async getDailyCity(actorId = "web-commander") {
      const store = await readStore();
      if (!store.dailyCities[actorId]) {
        store.dailyCities[actorId] = emptyDailyCity(actorId);
        await save(store);
      }
      return store.dailyCities[actorId];
    },
    async saveDailyCity(actorId = "web-commander", plan = {}) {
      const store = await readStore();
      const previous = store.dailyCities[actorId] || emptyDailyCity(actorId);
      const resolvedPlan = normalizeDailyPlan(plan);
      if (!resolvedPlan.assetCount) throw new Error("Deploy at least one defense asset before saving the daily plan.");
      const city = { ...previous, assets: resolvedPlan.assets, revision: previous.revision + 1, updatedAt: new Date().toISOString() };
      store.dailyCities[actorId] = city;
      store.events.push(event(`daily-city-${actorId}`, store.events.length + 1, "mission.started", Date.now(), `${actorId} updated the persistent daily city plan.`, { payload: { command: "daily.plan.save", assetCount: resolvedPlan.assetCount } }));
      await save(store);
      return city;
    },
    async getDailyReport(key = dayKey(), plan = {}, actorId = "web-commander") {
      const store = await readStore();
      const reportKey = dailyReportKey(actorId, key);
      if (store.dailyReports[reportKey]) return { report: store.dailyReports[reportKey], run: store.runs[store.dailyReports[reportKey].runId], city: store.dailyCities[actorId] || emptyDailyCity(actorId) };
      const suppliedPlan = normalizeDailyPlan(plan);
      const city = store.dailyCities[actorId] || emptyDailyCity(actorId);
      const resolvedPlan = suppliedPlan.assetCount ? suppliedPlan : normalizeDailyPlan({ assets: city.assets });
      if (!resolvedPlan.assetCount) return { report: null, run: null, city };
      const defenseBonus = defenseBonusFor(resolvedPlan);
      const run = simulateMission(`daily-${key}-${actorId}`, new Date().toISOString(), defenseBonus);
      store.runs[run.id] = { ...run, metadata: { source: "daily", dayKey: key, actorId, plan: resolvedPlan, defenseBonus } };
      store.events.push(...run.events);
      const nextCity = { ...city, assets: resolvedPlan.assets.map((asset) => ({ ...asset, readiness: Math.max(35, Math.round(asset.readiness - (run.impacts ? 7 : 2)) ) })), morale: Math.max(0, city.morale - run.impacts * 3), energy: Math.max(0, city.energy - run.impacts * 2), infrastructure: Math.max(0, city.infrastructure - run.impacts * 2), damage: Math.min(100, city.damage + run.impacts * 4), lastResolvedDay: key, revision: city.revision + 1, updatedAt: new Date().toISOString() };
      const report = { id: `daily-${key}-${stableHash(actorId)}`, cityId: nextCity.id, dayKey: key, runId: run.id, summary: `${run.interceptions} interceptions, ${run.impacts} impacts from ${resolvedPlan.assetCount} prepared defense asset(s).`, replayId: run.id, recommendedAction: run.impacts ? "Reinforce the east sector before the next night." : "Use the stable night to recover readiness." };
      store.dailyCities[actorId] = nextCity;
      store.dailyReports[reportKey] = report;
      store.notificationOutbox.push({ id: `notice-${key}-${stableHash(actorId)}`, type: "daily.report.ready", actorId, createdAt: new Date().toISOString(), payload: { dayKey: key, reportId: report.id } });
      await save(store);
      return { report, run: store.runs[run.id], city: nextCity };
    },
    async campaignState(actorId = "web-commander") {
      const store = await readStore();
      const progress = store.campaigns[actorId] || { currentMissionId: missions[0].id, completedMissionIds: [], lastRunId: null };
      return { ...progress, missions: missions.map((entry, index) => ({ id: entry.id, title: entry.title, index: index + 1, status: progress.completedMissionIds.includes(entry.id) ? "completed" : progress.currentMissionId === entry.id ? "active" : "locked" })) };
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
      const defenseBonus = defenseBonusFor(resolvedPlan);
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
        store.rooms[roomId] = { id: roomId, mode: "async", cityId: "city-01", revision: 1, sectorAssignments: { hq: "hq" }, members: [{ userId: "hq", role: "hq", ready: true }], commandLog: [], assets: [] };
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
      if (type === "asset.place") {
        const asset = { id: String(payload.batteryId || `asset-${sequence}`), kind: String(payload.kind || "unknown"), cityId: String(payload.cityId || "unknown"), readiness: Math.max(0, Math.min(100, Number(payload.readiness || 0))), sectorId, ownerId: actorId, position: payload.position || null };
        room.assets = (room.assets || []).filter((item) => item.id !== asset.id).concat(asset);
      }
      if (type === "asset.remove") room.assets = (room.assets || []).filter((item) => item.id !== String(payload.batteryId || ""));
      room.commandLog.push(command); room.revision += 1; store.rooms[roomId] = room; store.events.push(command); await save(store);
      return room;
    },
    async resolveCoOpRoom(roomId, actorId) {
      const room = await this.getRoom(roomId);
      if (!room.assets?.length) throw new Error("The co-op room needs at least one deployed defense asset.");
      const plan = normalizeDailyPlan({ assets: room.assets });
      const run = await this.runMission(`coop-${roomId}-${room.revision}`, actorId, plan, missions[0].id, "co-op");
      return { room, run };
    },
    async notificationOutbox() { return (await readStore()).notificationOutbox; },
    async setNotificationPreference(userId, chatId, enabled) {
      const store = await readStore();
      store.notificationPreferences[userId] = { chatId: String(chatId), enabled: Boolean(enabled), updatedAt: new Date().toISOString() };
      await save(store);
      return store.notificationPreferences[userId];
    },
    async pendingNotificationDeliveries() {
      const store = await readStore();
      return store.notificationOutbox.flatMap((item) => Object.entries(store.notificationPreferences).filter(([userId, preference]) => preference.enabled && (!item.actorId || item.actorId === userId) && !(item.deliveredTo || []).includes(preference.chatId)).map(([, preference]) => ({ item, chatId: preference.chatId })));
    },
    async markNotificationDelivered(notificationId, chatId) {
      const store = await readStore();
      const item = store.notificationOutbox.find((entry) => entry.id === notificationId);
      if (!item) return;
      item.deliveredTo = [...new Set([...(item.deliveredTo || []), String(chatId)])];
      await save(store);
    },
  };
}
