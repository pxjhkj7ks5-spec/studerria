import { localGameRepository } from "./localGameRepository";
import { campaignMissions } from "./missions";
import { runDeterministicMission } from "../game/deterministicMission";
import type { CampaignProgress, CoOpRoom, CommandRepository, DailyDefensePlan, DailyReport, LeaderboardEntry, MissionDefinition, MissionRun, PersistentDailyCity, RankedChallenge, RankedResult, SectorId } from "../domain/contracts";

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
  async runMission(mission: MissionDefinition, seed: string, plan?: DailyDefensePlan): Promise<MissionRun> {
    try { return await request<MissionRun>("/missions/run", { method: "POST", body: JSON.stringify({ missionId: mission.id, seed, plan, source: mission.modeId === "campaign" ? "campaign" : "command" }) }); }
    catch { return localGameRepository.runMission(mission, seed); }
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
    try { return await request<MissionRun>(`/runs/${encodeURIComponent(runId)}`); }
    catch { return runDeterministicMission(campaignMissions[0], runId.replace(/^run-/, "fallback-")); }
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
    await request<{ ok: true }>("/campaign/commands", { method: "POST", body: JSON.stringify(command) });
  },
  async getCampaignProgress(): Promise<CampaignProgress> { return request<CampaignProgress>("/campaign/state"); },
  async getDailyCity(): Promise<PersistentDailyCity> { return request<PersistentDailyCity>("/daily/city"); },
  async saveDailyCity(plan: DailyDefensePlan): Promise<PersistentDailyCity> { return request<PersistentDailyCity>("/daily/city", { method: "POST", body: JSON.stringify({ plan }) }); },
  async resolveCoOpRoom(roomId: string): Promise<{ room: CoOpRoom; run: MissionRun }> { return request<{ room: CoOpRoom; run: MissionRun }>(`/rooms/${encodeURIComponent(roomId)}/resolve`, { method: "POST" }); },
};
