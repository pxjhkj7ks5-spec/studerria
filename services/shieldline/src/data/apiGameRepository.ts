import { localGameRepository } from "./localGameRepository";
import { campaignMissions } from "./missions";
import { runDeterministicMission } from "../game/deterministicMission";
import { cacheOperationRun, enqueuePendingCommand, getCachedOperationRun } from "../platform/offlineStore";
import type { CampaignProgress, CoOpRoom, CommandRepository, DailyDefensePlan, DailyReport, LeaderboardEntry, MissionDefinition, MissionRun, OperationCommandInput, OperationCreateResult, PersistentDailyCity, RankedChallenge, RankedResult, ReplaySnapshot, SectorId, SimulationEvent } from "../domain/contracts";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${import.meta.env.BASE_URL}api${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  if (!response.ok) throw new Error((await response.json().catch(() => ({ error: "Request failed." }))).error || "Request failed.");
  return response.json() as Promise<T>;
}

/** Uses the authoritative sidecar when available, with a standalone-dev fallback. */
export const apiGameRepository: CommandRepository = {
  async createOperation(input): Promise<OperationCreateResult> {
    const body = JSON.stringify(input);
    try {
      const result = await request<OperationCreateResult>("/operations", { method: "POST", body });
      await cacheOperationRun(result.run);
      return result;
    } catch (error) {
      if (input.modeId !== "campaign") throw error;
      const mission = campaignMissions.find((entry) => entry.id === input.missionId) || campaignMissions[0];
      const run = await localGameRepository.runMission(mission, input.seed, input.plan);
      await cacheOperationRun(run);
      await enqueuePendingCommand({ path: "/operations", method: "POST", body });
      return { runId: run.id, revision: run.revision || 1, status: "completed", seed: run.seed, simVersion: run.simVersion || "2.1.0", run };
    }
  },
  async getOperation(runId: string): Promise<MissionRun | null> {
    try {
      const run = await request<MissionRun>(`/operations/${encodeURIComponent(runId)}`);
      await cacheOperationRun(run);
      return run;
    } catch { return getCachedOperationRun(runId); }
  },
  async getOperationEvents(runId: string, after = 0): Promise<SimulationEvent[]> {
    try { return (await request<{ events: SimulationEvent[] }>(`/operations/${encodeURIComponent(runId)}/events?after=${Math.max(0, after)}`)).events; }
    catch { return (await getCachedOperationRun(runId))?.events.filter((event) => event.sequence > after) || []; }
  },
  async getOperationSnapshots(runId: string, tick?: number): Promise<ReplaySnapshot[]> {
    const query = tick === undefined ? "" : `?tick=${Math.max(0, tick)}`;
    try { return (await request<{ snapshots: ReplaySnapshot[] }>(`/operations/${encodeURIComponent(runId)}/snapshots${query}`)).snapshots; }
    catch {
      const snapshots = (await getCachedOperationRun(runId))?.snapshots || [];
      return tick === undefined ? snapshots : snapshots.filter((snapshot) => snapshot.tick <= tick);
    }
  },
  async sendOperationCommand(runId: string, command: OperationCommandInput): Promise<{ command: OperationCommandInput; revision: number; duplicate: boolean }> {
    return request(`/operations/${encodeURIComponent(runId)}/commands`, { method: "POST", body: JSON.stringify(command) });
  },
  async runMission(mission: MissionDefinition, seed: string, plan?: DailyDefensePlan): Promise<MissionRun> {
    try {
      const run = await request<MissionRun>("/missions/run", { method: "POST", body: JSON.stringify({ missionId: mission.id, seed, plan, source: mission.modeId === "campaign" ? "campaign" : "command" }) });
      await cacheOperationRun(run);
      return run;
    } catch { return localGameRepository.runMission(mission, seed, plan); }
  },
  async getDailyReport(dayKey: string, plan?: DailyDefensePlan): Promise<DailyReport | null> {
    try { return (await request<{ report: DailyReport }>("/daily/resolve", { method: "POST", body: JSON.stringify({ dayKey, plan }) })).report; }
    catch { return localGameRepository.getDailyReport(dayKey); }
  },
  async getLeaderboard(): Promise<LeaderboardEntry[]> {
    try { return (await request<{ entries: LeaderboardEntry[] }>("/leaderboard")).entries; }
    catch { return localGameRepository.getLeaderboard(); }
  },
  async getRun(runId: string): Promise<MissionRun | null> {
    try {
      const run = await request<MissionRun>(`/runs/${encodeURIComponent(runId)}`);
      await cacheOperationRun(run);
      return run;
    } catch { return (await getCachedOperationRun(runId)) || runDeterministicMission(campaignMissions[0], runId.replace(/^run-/, "fallback-")); }
  },
  async getCoOpRoom(roomId: string): Promise<CoOpRoom> { return request<CoOpRoom>(`/rooms/${encodeURIComponent(roomId)}`); },
  async claimCoOpSector(roomId: string, sectorId: SectorId): Promise<CoOpRoom> {
    return request<CoOpRoom>(`/rooms/${encodeURIComponent(roomId)}/claim`, { method: "POST", body: JSON.stringify({ sectorId }) });
  },
  async getRankedChallenge(dayKey?: string): Promise<RankedChallenge> { return request<RankedChallenge>(`/ranked/current${dayKey ? `?day=${encodeURIComponent(dayKey)}` : ""}`); },
  async submitRankedChallenge(challengeId: string, plan: DailyDefensePlan): Promise<RankedResult> {
    return request<RankedResult>("/ranked/submit", { method: "POST", body: JSON.stringify({ challengeId, plan }) });
  },
  async sendCoOpCommand(roomId: string, sectorId: SectorId, command: { type: string; payload: Record<string, unknown> }): Promise<CoOpRoom> {
    return request<CoOpRoom>(`/rooms/${encodeURIComponent(roomId)}/commands`, { method: "POST", body: JSON.stringify({ sectorId, ...command }) });
  },
  async recordCampaignCommand(command: { type: string; payload: Record<string, unknown> }): Promise<void> {
    const body = JSON.stringify(command);
    try { await request<{ ok: true }>("/campaign/commands", { method: "POST", body }); }
    catch {
      await enqueuePendingCommand({ path: "/campaign/commands", method: "POST", body });
    }
  },
  async getCampaignProgress(): Promise<CampaignProgress> { return request<CampaignProgress>("/campaign/state"); },
  async getDailyCity(): Promise<PersistentDailyCity> { return request<PersistentDailyCity>("/daily/city"); },
  async saveDailyCity(plan: DailyDefensePlan): Promise<PersistentDailyCity> {
    const body = JSON.stringify({ plan });
    try { return await request<PersistentDailyCity>("/daily/city", { method: "POST", body }); }
    catch {
      await enqueuePendingCommand({ path: "/daily/city", method: "POST", body });
      throw new Error("Daily city save queued until Shieldline is online.");
    }
  },
  async resolveCoOpRoom(roomId: string): Promise<{ room: CoOpRoom; run: MissionRun }> { return request<{ room: CoOpRoom; run: MissionRun }>(`/rooms/${encodeURIComponent(roomId)}/resolve`, { method: "POST" }); },
};
