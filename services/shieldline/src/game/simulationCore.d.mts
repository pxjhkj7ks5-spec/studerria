import type { DailyDefensePlan, MissionDefinition, MissionRun } from "../domain/contracts";

export const SIM_VERSION: string;

export interface SimulationCoreInput {
  mission: MissionDefinition;
  seed: string;
  plan?: Partial<DailyDefensePlan>;
  defenseBonus?: number;
  startedAt?: string;
}

export function stableHash(value: string): string;
export function calculateDefenseBonus(plan?: Partial<DailyDefensePlan>): number;
export function simulateOperation(input: SimulationCoreInput): MissionRun;
