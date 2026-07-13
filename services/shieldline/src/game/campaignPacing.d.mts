import type { CampaignAttackSchedule, LaunchDirection, ThreatKind } from "../types/game";
import type { ThreatWave } from "../domain/contracts";

export const GUIDED_THREE_STAGE_PROFILE: "guided-three-stage";
export const launchSectorIdsByDirection: Record<LaunchDirection, string[]>;
export function shuffleLaunchDirections(random?: () => number): LaunchDirection[];
export function cruiseKindForDirection(direction: LaunchDirection): "kh101" | "kalibr";
export function guidedThreatKind(stageIndex: number, launchIndex: number, direction: LaunchDirection, random?: () => number): ThreatKind;
export function guidedStageLaunchCount(stageIndex: number): number;
export function guidedStageForElapsed(elapsedMs: number): number;
export function nextGuidedLaunchDelayMs(random?: () => number): number;
export function createGuidedCampaignSchedule(startedAtMs: number, random?: () => number): CampaignAttackSchedule;
export function createGuidedOperationWaves(random?: () => number): ThreatWave[];
export function sectorIdsForDirection(direction: LaunchDirection): string[];
