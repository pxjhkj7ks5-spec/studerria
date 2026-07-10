import { simulateOperation } from "./simulationCore.mjs";
import type { DailyDefensePlan, MissionDefinition, MissionRun } from "../domain/contracts";

/** Offline adapter over the exact same pure core used by the authoritative server. */
export function runDeterministicMission(mission: MissionDefinition, seed: string, plan: Partial<DailyDefensePlan> = {}): MissionRun {
  return simulateOperation({ mission, seed, plan });
}
