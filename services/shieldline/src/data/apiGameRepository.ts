import { localGameRepository } from "./localGameRepository";
import { campaignMissions } from "./missions";
import { runDeterministicMission } from "../game/deterministicMission";
import type { CoOpRoom, CommandRepository, DailyDefensePlan, DailyReport, LeaderboardEntry, MissionDefinition, MissionRun, SectorId } from "../domain/contracts";

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
  async runMission(mission: MissionDefinition, seed: string): Promise<MissionRun> {
    try { return await request<MissionRun>("/missions/run", { method: "POST", body: JSON.stringify({ missionId: mission.id, seed }) }); }
    catch { return localGameRepository.runMission(mission, seed); }
  },
  async getDailyReport(dayKey: string, plan?: DailyDefensePlan): Promise<DailyReport | null> {
    try { return (await request<{ report: DailyReport }>(`/daily?day=${encodeURIComponent(dayKey)}&assets=${Math.max(0, plan?.assetCount || 0)}`)).report; }
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
};
