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

export interface Resources {
  budget: number;
  ammo: number;
  energy: number;
  morale: number;
  political: number;
}

export interface IntelEntry {
  id: string;
  day: number;
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

export interface DailyForecast {
  day: number;
  weather: "clear" | "poor" | "storm";
  supportDelay: boolean;
  pressure: number;
  vagueWarning: string;
}

export interface GameState {
  day: number;
  status: CampaignStatus;
  statusReason: string;
  resources: Resources;
  cities: City[];
  infrastructure: InfrastructureNode[];
  units: DeployedUnit[];
  log: IntelEntry[];
  forecast: DailyForecast;
}
