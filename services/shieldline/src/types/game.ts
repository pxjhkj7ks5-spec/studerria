export type CityId =
  | "kyiv"
  | "lviv"
  | "odesa"
  | "dnipro"
  | "kharkiv"
  | "zaporizhzhia"
  | "mykolaiv"
  | "chernihiv"
  | "sumy"
  | "poltava"
  | "cherkasy"
  | "kropyvnytskyi"
  | "kryvyi-rih"
  | "zhytomyr"
  | "vinnytsia"
  | "khmelnytskyi"
  | "ternopil"
  | "rivne"
  | "lutsk"
  | "ivano-frankivsk"
  | "uzhhorod"
  | "chernivtsi";

export type InfrastructureKind = "energy" | "logistics" | "industry" | "communications";

export type UnitKind =
  | "radar"
  | "mvg"
  | "boat"
  | "ew"
  | "manpads"
  | "gepard"
  | "buk"
  | "s300"
  | "iris-t"
  | "nasams"
  | "patriot"
  | "drone-operators";

export type ThreatKind =
  | "drone"
  | "ballistic"
  | "cruise"
  | "decoy"
  | "combined"
  | "saturation"
  | "geran2"
  | "gerbera"
  | "parodiya"
  | "kh101"
  | "kalibr"
  | "iskander";

export type LaunchThreatProfile =
  | "shahed"
  | "gerbera"
  | "parodiya"
  | "iskander_m"
  | "s400_ballistic"
  | "s300_ballistic"
  | "decoy_ballistic"
  | "italmas"
  | "decoy"
  | "kh59"
  | "kalibr"
  | "kh31p"
  | "decoy_cruise"
  | "kh101"
  | "kh555";

export type CarrierKind = "tu95" | "black-sea-ship";

export type LaunchAreaState = "idle" | "warning" | "launching" | "cooldown";

export type CityAlertState = "calm" | "launch-corridor" | "probable-target" | "air-raid";

export type IntelTone = "info" | "success" | "warning" | "danger";
export type BattleNoticeType = "launch" | "detection";

export type CampaignStatus = "active" | "won" | "lost";

export type CoverageTier = "I" | "II" | "III";

export type ThreatStatus = "inbound" | "engaged" | "intercepted" | "impact";

export type CampaignMode = "training" | "seven-day" | "crisis" | "sandbox";

export type MapMode = "live" | "threats" | "coverage" | "logistics";

export type DifficultyLevel = "training" | "standard" | "hard" | "endurance";

export type CyclePhase = "planning" | "attack" | "recovery";

export type AttackArchetype =
  | "probe"
  | "saturation"
  | "infrastructure"
  | "decoy-screen"
  | "pressure"
  | "combined";

export type PlanningActionId =
  | "high-alert"
  | "conserve-ammo"
  | "emergency-aid"
  | "energy-repair"
  | "morale-campaign"
  | "rapid-redeployment"
  | "intelligence-focus";

export type UnitStatus = "ready" | "engaging" | "strained" | "exhausted" | "maintenance" | "redeploying" | "reloading";

export type SupplyStatus = "well-supplied" | "strained" | "undersupplied";

export type ShotStyle = "missile" | "gun" | "drone" | "ew";

export interface Coordinates {
  lat: number;
  lng: number;
}

export interface City {
  id: CityId;
  name: string;
  coordinates: Coordinates;
  infrastructure: number;
  morale: number;
  energy: number;
  importance: number;
  damage: number;
  alertState?: CityAlertState;
}

export interface InfrastructureNode {
  id: string;
  name: string;
  kind: InfrastructureKind;
  cityId: CityId;
  coordinates: Coordinates;
  integrity: number;
  critical: boolean;
}

export interface UnitDefinition {
  kind: UnitKind;
  name: string;
  shortName: string;
  technicalCode: string;
  cost: number;
  costLabel: string;
  upkeep: number;
  rangeLevel: number;
  detectionBonus: number;
  interceptionPower: number;
  ammoUse: number;
  ammoCapacity: number | "infinite";
  reloadMs: number;
  shotCooldownMs: number;
  salvoSize: number;
  primaryRangeKm: number;
  outerRangeKm: number;
  primaryAccuracy: number;
  outerAccuracy: number;
  engagementMode: "detect" | "kinetic" | "disrupt";
  engagementChanceByThreat: Record<ThreatKind, number>;
  mobility: number;
  readiness: number;
  repairEffect?: number;
  logisticsEffect?: number;
  description: string;
}

export interface DeployedUnit {
  id: string;
  kind: UnitKind;
  cityId: CityId;
  readiness: number;
}

export interface DefenseBattery {
  id: string;
  kind: UnitKind;
  position: Coordinates;
  coverageTier: CoverageTier;
  coverageRadius: number;
  readiness: number;
  fatigue: number;
  daysSinceMaintenance: number;
  lastAction: string;
  lastEngagementResult: string;
  status: UnitStatus;
  supplyStatus: SupplyStatus;
  cooldownMs: number;
  reloadRemainingMs: number;
  currentAmmo: number | "infinite";
  assignedCityId: CityId;
  health: number;
  experienceLevel: number;
  createdAtMission: number;
  lastMovedMission: number;
}

export interface LaunchSector {
  id: string;
  name: string;
  lat: number;
  lng: number;
  radiusKm: number;
  weight: number;
  threats: LaunchThreatProfile[];
  role: string;
  state?: LaunchAreaState;
  stateUntilMs?: number;
  warningStartedAtMs?: number;
  targetCityId?: CityId;
  targetCoordinates?: Coordinates;
  targetHeadingDeg?: number;
  lastLaunchCoordinates?: Coordinates;
  activeThreatKind?: ThreatKind;
}

export type LaunchDirection = "north" | "east" | "south";

export interface CampaignAttackSchedule {
  profile: "guided-three-stage";
  directions: LaunchDirection[];
  stageIndex: number;
  stageLaunchCount: number;
  nextLaunchAtMs: number;
  ballisticLaunched: boolean;
}

export interface Resources {
  budget: number;
  ammo: number;
  energy: number;
  morale: number;
  political: number;
}

export interface IntelEntry {
  id: string;
  time: string;
  title: string;
  body: string;
  tone: IntelTone;
  eventType?: BattleNoticeType;
  locationLabel?: string;
}

export interface Threat {
  id: string;
  kind: ThreatKind;
  targetCityId: CityId;
  targetNodeId?: string;
  difficulty: number;
  saturation: number;
  disguisedAs?: ThreatKind;
}

export interface LiveThreat {
  id: string;
  kind: ThreatKind;
  status: ThreatStatus;
  origin: Coordinates;
  target: Coordinates;
  targetNodeId?: string;
  targetCityId: CityId;
  launchSectorId: string;
  launchSectorName: string;
  progress: number;
  speed: number;
  speedKph: number;
  altitudeM: number;
  difficulty: number;
  damage: number;
  confidence: number;
  saturation: number;
  attackPlanId?: string;
  archetype?: AttackArchetype;
  isFalseTrack?: boolean;
  plannedTargetPriority?: string;
  headingDeg: number;
  lastKnownPosition?: Coordinates;
  revealed: boolean;
  trackQuality: number;
  reward: number;
  carrierId?: string;
  routeId?: string;
  routeWaypoints?: Coordinates[];
  campaignPriority?: "low" | "medium" | "high" | "veryHigh" | "critical";
  campaignGroupId?: string;
}

export interface CampaignSpawnEvent {
  id: string;
  dueMs: number;
  threatKind: ThreatKind;
  routeId: string;
  groupId: string;
  mergeBehavior: string;
  priority: "low" | "medium" | "high" | "veryHigh" | "critical";
  targetRegion: string;
  mergeRouteId?: string;
  rallyRatio?: number;
}

export interface CampaignRewardLine {
  label: string;
  amount: number;
  kind: "grant" | "kill" | "bonus" | "penalty" | "cost";
}

export interface CampaignMissionResult {
  missionIndex: number;
  missionId: string;
  title: string;
  totalTargets: number;
  interceptions: number;
  impacts: number;
  killReward: number;
  bonusRewards: number;
  penaltyCosts: number;
  walletAfterMission: number;
  civilianResilienceAfterMission: number;
  rewardLines: CampaignRewardLine[];
}

export interface CampaignState {
  missionIndex: number;
  campaignWallet: number;
  civilianResilience: number;
  unlockedSystems: UnitKind[];
  previousMissionResults: CampaignMissionResult[];
  spawnEvents: CampaignSpawnEvent[];
  spawnCursor: number;
  missionKillReward: number;
  missionKillsByKind: Partial<Record<ThreatKind, number>>;
  missionInterceptionsAtStart: number;
  missionImpactsAtStart: number;
  missionGrant: number;
  missionGrantApplied: boolean;
  intermission: boolean;
  completed: boolean;
  tutorialStep: number;
}

export type EngagementResult = "success" | "miss" | "detected";

export interface EngagementEvent {
  id: string;
  unitId: string;
  targetId: string;
  unitType: UnitKind;
  startPosition: Coordinates;
  targetStartPosition: Coordinates;
  targetPredictedPosition: Coordinates;
  result: EngagementResult;
  startedAtMs: number;
  durationMs: number;
  progress: number;
  resolved: boolean;
  style: ShotStyle | "radar";
}

export type InterceptorShot = EngagementEvent;

export interface ImpactMarker {
  id: string;
  position: Coordinates;
  tone: "impact" | "intercept";
  ttlMs: number;
}

export interface DailyForecast {
  day: number;
  weather: "clear" | "poor" | "storm";
  supportDelay: boolean;
  pressure: number;
  vagueWarning: string;
}

export interface AttackPlan {
  id: string;
  day: number;
  archetype: AttackArchetype;
  intensity: number;
  deception: number;
  targetPriorities: InfrastructureKind[];
  threatMix: ThreatKind[];
  eventText: string;
}

export interface ThreatDirectorContext {
  resources: Resources;
  cityDamage: number;
  placedDefenseUnits: number;
  ammoLevel: number;
  moraleLevel: number;
  energyStability: number;
  intelligenceConfidence: number;
  currentDay: number;
  difficulty: DifficultyLevel;
  recentArchetypes: AttackArchetype[];
  weakSystems: InfrastructureKind[];
  threatDirectorBias?: Partial<Record<AttackArchetype, number>>;
}

export interface PlanningActionState {
  selected: PlanningActionId[];
  cooldowns: Partial<Record<PlanningActionId, number>>;
  usageCounts: Partial<Record<PlanningActionId, number>>;
  pendingAid: Array<{ arrivesDay: number; budget: number; ammo: number }>;
}

export interface SupplyNode {
  id: string;
  name: string;
  position: Coordinates;
  strength: number;
  cityId?: CityId;
  source: "infrastructure" | "battery";
}

export interface SupplyRoute {
  id: string;
  from: Coordinates;
  to: Coordinates;
  status: SupplyStatus;
  delayDays: number;
  label: string;
}

export interface CarrierTrack {
  id: string;
  kind: CarrierKind;
  position: Coordinates;
  launchSectorId: string;
  headingDeg: number;
  ttlMs: number;
}

export interface PendingLaunch {
  id: string;
  kind: ThreatKind;
  sectorId: string;
  targetCityId: CityId;
  origin: Coordinates;
  launchesAtMs: number;
}

export interface LogisticsState {
  nodes: SupplyNode[];
  routes: SupplyRoute[];
  citySupply: Partial<Record<CityId, SupplyStatus>>;
  unitSupply: Record<string, SupplyStatus>;
  resupplyDelayDays: number;
  ammoRecoveryMultiplier: number;
  repairRecoveryMultiplier: number;
}

export interface ScenarioDefinition {
  id: string;
  title: string;
  description: string;
  durationDays: number;
  difficulty: DifficultyLevel;
  startingResources: Resources;
  initialCityStateModifiers: Partial<Record<CityId, Partial<Pick<City, "infrastructure" | "morale" | "energy" | "damage">>>>;
  allowedUnits: UnitKind[];
  threatDirectorBias: Partial<Record<AttackArchetype, number>>;
  specialRules: string[];
  winConditions: string[];
  lossConditions: string[];
  pacingProfile?: "guided-three-stage";
}

export interface AfterActionReport {
  id: string;
  day: number;
  generatedAtMs: number;
  archetype?: AttackArchetype;
  situationSummary: string;
  threatOverview: {
    totalTracks: number;
    confirmedThreats: number;
    decoys: number;
    unidentifiedTracks: number;
  };
  defensePerformance: {
    interceptions: number;
    missedThreats: number;
    ammoSpent: number;
    averageReadinessChange: number;
    strongestUnit: string;
    weakestCoverageArea: string;
  };
  damageReport: {
    damagedCities: string[];
    systems: {
      infrastructure: number;
      energy: number;
      communications: number;
      logistics: number;
      civilMorale: number;
      repairCapacity: number;
    };
  };
  resourceChanges: {
    budget: number;
    ammo: number;
    energy: number;
    morale: number;
    political: number;
  };
  recommendation: string;
  actionEffects: string[];
  logisticsNotes: string[];
}

export interface CycleSnapshot {
  day: number;
  resources: Resources;
  cities: City[];
  infrastructure: InfrastructureNode[];
  batteries: DefenseBattery[];
  interceptions: number;
  impacts: number;
  ammo: number;
  threatCount: number;
}

export interface GameState {
  day: number;
  scenarioId: string;
  difficulty: DifficultyLevel;
  cyclePhase: CyclePhase;
  cycleStartedAtMs: number;
  cycleDurationMs: number;
  currentAttackPlan: AttackPlan | null;
  campaignAttackSchedule: CampaignAttackSchedule | null;
  attackPlanHistory: AttackPlan[];
  cycleSnapshot: CycleSnapshot | null;
  afterActionReports: AfterActionReport[];
  latestReportId: string | null;
  planningActions: PlanningActionState;
  logistics: LogisticsState;
  elapsedMs: number;
  wavePressure: number;
  status: CampaignStatus;
  statusReason: string;
  resources: Resources;
  cities: City[];
  infrastructure: InfrastructureNode[];
  launchSectors: LaunchSector[];
  carriers: CarrierTrack[];
  pendingLaunches: PendingLaunch[];
  units: DeployedUnit[];
  batteries: DefenseBattery[];
  storedBatteries: DefenseBattery[];
  liveThreats: LiveThreat[];
  engagementEvents: EngagementEvent[];
  impactMarkers: ImpactMarker[];
  interceptions: number;
  impacts: number;
  log: IntelEntry[];
  forecast: DailyForecast;
  placementWarning: string | null;
  campaign: CampaignState | null;
}
