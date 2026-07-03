export type CityId =
  | "kyiv"
  | "lviv"
  | "odesa"
  | "dnipro"
  | "kharkiv"
  | "zaporizhzhia"
  | "mykolaiv";

export type InfrastructureKind = "energy" | "logistics" | "industry" | "communications";

export type UnitKind =
  | "radar"
  | "mobile"
  | "short"
  | "medium"
  | "repair"
  | "logistics"
  | "intel"
  | "decoy";

export type ThreatKind = "drone" | "missile" | "decoy" | "combined" | "saturation";

export type IntelTone = "info" | "success" | "warning" | "danger";

export type CampaignStatus = "active" | "won" | "lost";

export type CoverageTier = "I" | "II" | "III";

export type ThreatStatus = "inbound" | "detected" | "engaged" | "intercepted" | "impact";

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
  cost: number;
  upkeep: number;
  rangeLevel: number;
  detectionBonus: number;
  interceptionPower: number;
  ammoUse: number;
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
  cooldownMs: number;
  assignedCityId: CityId;
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
}

export interface Threat {
  id: string;
  kind: ThreatKind;
  targetCityId: CityId;
  targetNodeId: string;
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
  targetNodeId: string;
  targetCityId: CityId;
  progress: number;
  speed: number;
  difficulty: number;
  damage: number;
  detected: boolean;
  saturation: number;
}

export interface InterceptorShot {
  id: string;
  batteryId: string;
  threatId: string;
  from: Coordinates;
  to: Coordinates;
  progress: number;
  speed: number;
}

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

export interface GameState {
  day: number;
  elapsedMs: number;
  wavePressure: number;
  status: CampaignStatus;
  statusReason: string;
  resources: Resources;
  cities: City[];
  infrastructure: InfrastructureNode[];
  units: DeployedUnit[];
  batteries: DefenseBattery[];
  liveThreats: LiveThreat[];
  interceptorShots: InterceptorShot[];
  impactMarkers: ImpactMarker[];
  interceptions: number;
  impacts: number;
  log: IntelEntry[];
  forecast: DailyForecast;
}
