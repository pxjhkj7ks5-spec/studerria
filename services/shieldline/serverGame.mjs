import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname } from "node:path";
import { SIM_VERSION, calculateDefenseBonus, simulateOperation, stableHash } from "./src/game/simulationCore.mjs";
import { ALL_LAUNCH_SECTOR_IDS, FIRST_NIGHT_LAUNCH_SECTOR_IDS, SECOND_NIGHT_LAUNCH_SECTOR_IDS } from "./src/game/launchSystem.mjs";

const DEFAULT_STORE = { version: 3, events: [], runs: {}, dailyReports: {}, dailyCities: {}, campaigns: {}, rankedSubmissions: {}, rooms: {}, notificationOutbox: [], notificationPreferences: {}, operationCommands: {}, operationRevisions: {} };
const VALID_ASSET_KINDS = new Set(["radar", "mvg", "boat", "ew", "manpads", "gepard", "buk", "s300", "iris-t", "nasams", "patriot", "drone-operators"]);
const missions = [
  {
    id: "campaign-night-01",
    title: "Night 01: Signal Window",
    launchSectorIds: FIRST_NIGHT_LAUNCH_SECTOR_IDS,
    waves: [
    { id: "wave-01", originSector: "east", targetSector: "east", etaSeconds: 28, size: 8, difficulty: 42, threatKind: "geran2" },
    { id: "wave-02", originSector: "north", targetSector: "north", etaSeconds: 52, size: 3, difficulty: 62, threatKind: "iskander" },
    { id: "wave-03", originSector: "south", targetSector: "west", etaSeconds: 75, size: 6, difficulty: 48, threatKind: "gerbera" },
  ],
  },
  {
    id: "campaign-night-02",
    title: "Night 02: Blackout Relay",
    launchSectorIds: SECOND_NIGHT_LAUNCH_SECTOR_IDS,
    waves: [
      { id: "wave-01", originSector: "south", targetSector: "south", etaSeconds: 24, size: 10, difficulty: 48, threatKind: "geran2" },
      { id: "wave-02", originSector: "east", targetSector: "east", etaSeconds: 50, size: 5, difficulty: 67, threatKind: "kalibr" },
      { id: "wave-03", originSector: "north", targetSector: "east", etaSeconds: 79, size: 4, difficulty: 72, threatKind: "kh101" },
    ],
  },
  {
    id: "campaign-night-03",
    title: "Night 03: Last Reserve",
    launchSectorIds: ALL_LAUNCH_SECTOR_IDS,
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

function event(runId, sequence, type, occurredAtMs, message, extras = {}) {
  return { id: `${runId}-evt-${sequence}`, runId, sequence, type, occurredAtMs, tick: occurredAtMs, simVersion: SIM_VERSION, schemaVersion: 1, message, payload: {}, ...extras };
}

export function simulateMission(seed, now = new Date().toISOString(), defenseBonus = 0, missionId = missions[0].id) {
  return simulateOperation({ mission: missionById(missionId), seed, defenseBonus, startedAt: now });
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
  return calculateDefenseBonus(plan);
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
    async getRunEvents(runId, after = 0) {
      const run = (await readStore()).runs[runId];
      return run ? run.events.filter((entry) => entry.sequence > after) : null;
    },
    async getRunSnapshots(runId, tick = Number.POSITIVE_INFINITY) {
      const run = (await readStore()).runs[runId];
      return run ? (run.snapshots || []).filter((snapshot) => snapshot.tick <= tick) : null;
    },
    async appendOperationCommand(runId, actorId, input = {}) {
      const store = await readStore();
      if (!store.runs[runId]) throw Object.assign(new Error("Operation not found."), { statusCode: 404 });
      const commandId = String(input.commandId || "").slice(0, 96);
      if (!commandId) throw new Error("commandId is required.");
      const commands = store.operationCommands[runId] || [];
      const existing = commands.find((entry) => entry.commandId === commandId);
      if (existing) return { command: existing, revision: store.operationRevisions[runId] || 1, duplicate: true };
      const revision = store.operationRevisions[runId] || 1;
      if (Number(input.baseRevision) !== revision) {
        throw Object.assign(new Error("Operation revision conflict."), { statusCode: 409, latestPatch: { revision, commands: commands.slice(-20) } });
      }
      const command = { commandId, runId, actorId, revision: revision + 1, scope: input.scope || { type: "operation" }, type: String(input.type || "unknown").slice(0, 64), payload: input.payload || {}, acceptedAt: new Date().toISOString() };
      store.operationCommands[runId] = [...commands, command];
      store.operationRevisions[runId] = revision + 1;
      await save(store);
      return { command, revision: revision + 1, duplicate: false };
    },
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
