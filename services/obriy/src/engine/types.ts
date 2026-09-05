export type ThreatType =
  | "uav"
  | "fpv"
  | "recon"
  | "missile"
  | "ballistic"
  | "kab"
  | "mig31k"
  | "unknown"
  | "other";
export type AlertLevel = "INFO" | "WATCH" | "WARNING" | "HIGH" | "RESOLVED";
export interface SourceReference {
  provider: string;
  externalId: string;
  independence: "unknown" | "independent" | "overlapping";
}

export interface NormalizedTrack {
  internalId: string;
  source: {
    primary: "neptun";
    externalTrackId: string;
    sourceRefs: SourceReference[];
  };
  threat: {
    type: ThreatType;
    upstreamType: string;
    title?: string;
    groupCount?: number;
  };
  position: {
    lat?: number;
    lon?: number;
    quality: "confirmed" | "approx" | "unknown";
    uncertaintyKm?: number;
    areaOnly: boolean;
  };
  motion: {
    headingDeg?: number;
    speedKmh?: number;
    confirmedAt?: string;
    presumptive: boolean;
  };
  confidence: {
    upstreamLevel: "low" | "medium" | "high" | "unknown";
    sourceCount?: number;
  };
  geography: { region?: string; district?: string; locality?: string };
  status: "active" | "stale" | "resolved" | "unknown";
  advisory: boolean;
  observedAt: string;
  updatedAt: string;
  ingestedAt: string;
  rawSchemaVersion: number;
  raw?: Record<string, unknown>;
}

export interface OfficialAlertEvent {
  provider: "alerts.in.ua" | "neptun";
  externalId: string;
  regionUid?: string;
  raionUid?: string;
  oblast?: string;
  raion?: string;
  locality?: string;
  kind:
    | "air_raid"
    | "artillery_shelling"
    | "urban_fights"
    | "chemical"
    | "nuclear"
    | "unknown";
  active: boolean;
  calculated?: boolean;
  startedAt?: string;
  updatedAt: string;
  ingestedAt: string;
}

export interface Zone {
  id: string;
  userId: string;
  label: string;
  lat: number;
  lon: number;
  radiusKm: number;
  regionUid?: string;
  oblast?: string;
  enabled: boolean;
}
export interface Point {
  lat: number;
  lon: number;
}
export interface RiskFactors {
  evidence: number;
  freshness: number;
  proximity: number;
  approaching: number;
  corridorHit: number;
  officialContext: number;
}
export type ExplanationCode =
  | "AREA_ONLY"
  | "ADVISORY"
  | "STALE"
  | "APPROACHING"
  | "CORRIDOR_INTERSECTION"
  | "OFFICIAL_ALERT_ACTIVE"
  | "HIGH_UPSTREAM_CONFIDENCE"
  | "LOW_POSITION_QUALITY"
  | "INSUFFICIENT_MOTION"
  | "POSITION_UNAVAILABLE"
  | "SOURCE_RESOLVED"
  | "ZONE_DISABLED"
  | "SOURCE_STATUS_UNKNOWN"
  | "PREDICTION_HORIZON_EXHAUSTED"
  | "UNCERTAINTY_DOMINATES"
  | "TURNING_AWAY"
  | "NEAR_MISS";

export interface RiskAssessment {
  version: "1";
  assessmentId: string;
  trackId: string;
  zoneId: string;
  evaluatedAt: string;
  sourceUpdatedAt: string;
  level: Exclude<AlertLevel, "RESOLVED">;
  score: number;
  factors: RiskFactors;
  geometry: {
    currentDistanceKm?: number;
    distanceBand?: string;
    minimumPredictedDistanceKm?: number;
    forecastHorizonSeconds?: number;
    uncertaintyKm?: number;
    corridorIntersects: boolean;
    strongCorridorIntersection?: boolean;
    headingError?: number;
    bearingToZone?: number;
    distanceTrend?: "approaching" | "receding" | "steady" | "unknown";
    /** Internal corridor interval, never an arrival time or notification payload. */
    firstPossibleCorridorEntry?: { fromSeconds: number; toSeconds: number };
  };
  explanationCodes: ExplanationCode[];
  engineConfigVersion: string;
  escalationAllowed: boolean;
  resolved: boolean;
}

/** Persist one JSON value per user / zone / track in the same transaction as the outbox. */
export interface AlertState {
  currentLevel: AlertLevel;
  lastScore: number;
  lastDistanceBand?: string;
  lastDistanceBandRank?: number;
  lastNotifiedDistanceBandRank?: number;
  lastNotificationAt?: string;
  consecutiveAbove: number;
  consecutiveBelow: number;
  pendingLevel?: AlertLevel;
  lastHeadingBucket?: number;
  lastApproaching?: boolean;
  lastCorridorIntersects?: boolean;
  resolvedAt?: string;
  lastEventKey?: string;
  recentEventKeys?: string[];
  lastSourceUpdatedAt?: string;
  lastEvaluatedAt?: string;
  hadHighLevelNotification?: boolean;
  lastNotifiedLevel?: AlertLevel;
}
