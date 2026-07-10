import { campaignMissions } from "./missions";
import { runDeterministicMission } from "../game/deterministicMission";
import type { DailyDefensePlan, DailyReport, LeaderboardEntry, MissionDefinition, MissionRun, SimulationRepository } from "../domain/contracts";

/** Local adapter only. It is deliberately shaped as an async API repository. */
export const localGameRepository: SimulationRepository = {
  async runMission(mission: MissionDefinition, seed: string, plan?: DailyDefensePlan): Promise<MissionRun> {
    return runDeterministicMission(mission, seed, plan);
  },
  async getDailyReport(dayKey: string): Promise<DailyReport | null> {
    const run = runDeterministicMission(campaignMissions[0], `daily-${dayKey}`);
    return { id: `daily-${dayKey}`, cityId: "city-01", dayKey, runId: run.id, summary: `${run.interceptions} interceptions, ${run.impacts} impacts.`, replayId: run.id, recommendedAction: "Reinforce the east sector before the next night." };
  },
  async getLeaderboard(): Promise<LeaderboardEntry[]> {
    return [
      { rank: 1, userId: "sim-1", displayName: "Kite", score: 942, result: "victory", updatedAt: "2026-07-09T00:00:00.000Z" },
      { rank: 2, userId: "sim-2", displayName: "Orion", score: 918, result: "victory", updatedAt: "2026-07-09T00:00:00.000Z" },
      { rank: 3, userId: "sim-3", displayName: "You", score: 870, result: "contained", updatedAt: "2026-07-09T00:00:00.000Z" },
    ];
  },
};
