import type { Coordinates, Resources, ThreatKind, UnitKind } from "../types/game";

/**
 * The client contracts intentionally mirror the API boundary.  Local adapters use
 * these shapes today; the server-side command/event store can replace them without
 * changing the game shell.
 */
export type GameModeId = "campaign" | "rapid-response" | "ranked-challenge" | "co-op-command" | "sandbox" | "training" | "daily-defense";
export type SectorId = "north" | "south" | "east" | "west" | "hq";
export type OperationPhase = "planning" | "countdown" | "running" | "paused" | "completed";
export type SimulationSpeed = 1 | 8 | 60 | 600;
export type SimulationEventType =
  | "mission.started"
  | "launch.warning"
  | "threat.launched"
  | "wave.detected"
  | "track.detected"
  | "battery.fired"
  | "interception"
  | "impact"
  | "mission.completed";

export interface GameModeRuntimePolicy {
  execution: "live" | "daily-scheduled";
  start: "auto-checklist" | "manual" | "sandbox-controls" | "hq-ready" | "scheduled";
  countdownMs: number;
  defaultSpeed: SimulationSpeed;
  availableSpeeds: SimulationSpeed[];
  requiresRadar: boolean;
  requiresKinetic: boolean;
}

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
  tick?: number;
  simVersion?: string;
  schemaVersion?: number;
  sectorId?: SectorId;
  waveId?: string;
  assetId?: string;
  message: string;
  targetId?: string;
  payload: Record<string, number | string | boolean | null>;
}

export interface ReplayEvent extends SimulationEvent {
  replayAtMs: number;
  route?: { from: SectorId; to: SectorId };
  interceptPoint?: { x: number; y: number };
}

export interface ReplaySnapshot {
  runId: string;
  sequence: number;
  tick: number;
  simVersion: string;
  state: Record<string, number | string | boolean | null>;
}

export interface MissionRun {
  id: string;
  missionId: string;
  seed: string;
  startedAt: string;
  completedAt: string;
  events: SimulationEvent[];
  replay: ReplayEvent[];
  snapshots?: ReplaySnapshot[];
  simVersion?: string;
  revision?: number;
  status?: "completed";
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

export interface PersistentDailyCity {
  id: string;
  ownerId: string;
  revision: number;
  morale: number;
  energy: number;
  infrastructure: number;
  damage: number;
  assets: DailyDefensePlan["assets"];
  lastResolvedDay: string | null;
  updatedAt: string;
}

export interface CampaignProgress {
  currentMissionId: string | null;
  completedMissionIds: string[];
  lastRunId: string | null;
  missions: Array<{ id: string; title: string; index: number; status: "completed" | "active" | "locked" }>;
}

export interface DailyDefensePlan {
  assetCount: number;
  radarCount: number;
  kineticCount: number;
  averageReadiness: number;
  assets: Array<{ id?: string; kind: string; cityId: string; readiness: number; position?: Coordinates }>;
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

export interface OperationCommandInput {
  commandId: string;
  baseRevision: number;
  scope: { type: "operation" | "sector"; sectorId?: SectorId };
  type: string;
  payload: Record<string, unknown>;
}

export interface OperationCreateResult {
  runId: string;
  revision: number;
  status: "completed";
  seed: string;
  simVersion: string;
  run: MissionRun;
}

export interface CoOpRoom {
  id: string;
  mode: "async" | "live";
  cityId: string;
  revision: number;
  sectorAssignments: Partial<Record<SectorId, string>>;
  members: Array<{ userId: string; role: SectorId; ready: boolean }>;
  commandLog: SimulationEvent[];
  assets?: Array<{ id: string; kind: string; cityId: string; readiness: number; sectorId: SectorId; ownerId: string; position?: Coordinates | null }>;
  viewerId?: string;
}

export interface SimulationRepository {
  runMission(mission: MissionDefinition, seed: string, plan?: DailyDefensePlan): Promise<MissionRun>;
  getDailyReport(dayKey: string, plan?: DailyDefensePlan): Promise<DailyReport | null>;
  getLeaderboard(): Promise<LeaderboardEntry[]>;
}

export interface CommandRepository extends SimulationRepository {
  createOperation(input: { modeId: Exclude<GameModeId, "daily-defense">; missionId: string; seed: string; plan: DailyDefensePlan }): Promise<OperationCreateResult>;
  getOperation(runId: string): Promise<MissionRun | null>;
  getOperationEvents(runId: string, after?: number): Promise<SimulationEvent[]>;
  getOperationSnapshots(runId: string, tick?: number): Promise<ReplaySnapshot[]>;
  sendOperationCommand(runId: string, command: OperationCommandInput): Promise<{ command: OperationCommandInput; revision: number; duplicate: boolean }>;
  getRun(runId: string): Promise<MissionRun | null>;
  getCoOpRoom(roomId: string): Promise<CoOpRoom>;
  claimCoOpSector(roomId: string, sectorId: SectorId): Promise<CoOpRoom>;
  getRankedChallenge(dayKey?: string): Promise<RankedChallenge>;
  submitRankedChallenge(challengeId: string, plan: DailyDefensePlan): Promise<RankedResult>;
  sendCoOpCommand(roomId: string, sectorId: SectorId, command: { type: string; payload: Record<string, unknown> }): Promise<CoOpRoom>;
  recordCampaignCommand(command: { type: string; payload: Record<string, unknown> }): Promise<void>;
  getCampaignProgress(): Promise<CampaignProgress>;
  getDailyCity(): Promise<PersistentDailyCity>;
  saveDailyCity(plan: DailyDefensePlan): Promise<PersistentDailyCity>;
  resolveCoOpRoom(roomId: string): Promise<{ room: CoOpRoom; run: MissionRun }>;
}
