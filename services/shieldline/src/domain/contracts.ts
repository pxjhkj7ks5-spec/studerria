import type { Coordinates, Resources, ThreatKind, UnitKind } from "../types/game";

/**
 * The client contracts intentionally mirror the API boundary.  Local adapters use
 * these shapes today; the server-side command/event store can replace them without
 * changing the game shell.
 */
export type GameModeId = "campaign" | "rapid-response" | "ranked-challenge" | "co-op-command" | "sandbox" | "training" | "daily-defense";
export type SectorId = "north" | "south" | "east" | "west" | "hq";
export type SimulationEventType = "mission.started" | "wave.detected" | "interception" | "impact" | "mission.completed";

export interface ShieldlineUser {
  id: string;
  displayName: string;
  platform: "telegram" | "web" | "pwa";
  telegramId?: string;
  cosmeticLoadout?: string[];
}

export interface CityProfile {
  id: string;
  name: string;
  morale: number;
  energy: number;
  infrastructure: number;
  sectors: CitySector[];
}

export interface CitySector {
  id: SectorId;
  name: string;
  position: { x: number; y: number };
  coverage: number;
  pressure: number;
  damage: number;
  ownerId?: string;
}

export interface DefenseAsset {
  id: string;
  kind: UnitKind | "civil-defense";
  name: string;
  sectorId: SectorId;
  readiness: number;
  ammo: number;
  position?: Coordinates;
}

export interface ThreatWave {
  id: string;
  index: number;
  threatKind: ThreatKind;
  originSector: SectorId;
  targetSector: SectorId;
  etaSeconds: number;
  size: number;
  difficulty: number;
}

export interface MissionDefinition {
  id: string;
  modeId: GameModeId;
  title: string;
  subtitle: string;
  durationMinutes: number;
  simulationSpeed: number;
  difficulty: "guided" | "standard" | "hard" | "expert";
  resources: Pick<Resources, "budget" | "ammo" | "morale" | "energy">;
  mainRisk: string;
  victoryCondition: string;
  briefing: string;
  waves: ThreatWave[];
}

export interface SimulationEvent {
  id: string;
  runId: string;
  sequence: number;
  type: SimulationEventType;
  occurredAtMs: number;
  sectorId?: SectorId;
  waveId?: string;
  assetId?: string;
  message: string;
  payload: Record<string, number | string | boolean>;
}

export interface ReplayEvent extends SimulationEvent {
  replayAtMs: number;
  route?: { from: SectorId; to: SectorId };
  interceptPoint?: { x: number; y: number };
}

export interface MissionRun {
  id: string;
  missionId: string;
  seed: string;
  startedAt: string;
  completedAt: string;
  events: SimulationEvent[];
  replay: ReplayEvent[];
  result: "victory" | "contained" | "setback";
  interceptions: number;
  impacts: number;
  ammoSpent: number;
  sectorSummary: Record<Exclude<SectorId, "hq">, Pick<CitySector, "coverage" | "pressure" | "damage">>;
}

export interface DailyReport {
  id: string;
  cityId: string;
  dayKey: string;
  runId: string;
  summary: string;
  replayId: string;
  recommendedAction: string;
}

export interface DailyDefensePlan {
  assetCount: number;
  radarCount: number;
  kineticCount: number;
  averageReadiness: number;
  assets: Array<{ kind: string; cityId: string; readiness: number }>;
}

export interface LeaderboardEntry {
  rank: number;
  userId: string;
  displayName: string;
  score: number;
  result: MissionRun["result"];
  updatedAt: string;
}

export interface RankedChallenge {
  id: string;
  dayKey: string;
  seed: string;
  title: string;
  rules: string[];
}

export interface RankedResult {
  challengeId: string;
  challenge: RankedChallenge;
  run: MissionRun;
  entry: LeaderboardEntry;
}

export interface CoOpRoom {
  id: string;
  mode: "async" | "live";
  cityId: string;
  revision: number;
  sectorAssignments: Partial<Record<SectorId, string>>;
  members: Array<{ userId: string; role: SectorId; ready: boolean }>;
  commandLog: SimulationEvent[];
  viewerId?: string;
}

export interface SimulationRepository {
  runMission(mission: MissionDefinition, seed: string): Promise<MissionRun>;
  getDailyReport(dayKey: string, plan?: DailyDefensePlan): Promise<DailyReport | null>;
  getLeaderboard(): Promise<LeaderboardEntry[]>;
}

export interface CommandRepository extends SimulationRepository {
  getRun(runId: string): Promise<MissionRun | null>;
  getCoOpRoom(roomId: string): Promise<CoOpRoom>;
  claimCoOpSector(roomId: string, sectorId: SectorId): Promise<CoOpRoom>;
  getRankedChallenge(dayKey?: string): Promise<RankedChallenge>;
  submitRankedChallenge(challengeId: string, plan: DailyDefensePlan): Promise<RankedResult>;
  sendCoOpCommand(roomId: string, sectorId: SectorId, command: { type: string; payload: Record<string, string | number> }): Promise<CoOpRoom>;
}
