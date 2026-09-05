export interface EngineConfig {
  version: string;
  weights: {
    evidence: number;
    freshness: number;
    proximity: number;
    approaching: number;
    corridorHit: number;
    officialContext: number;
  };
  evidence: {
    base: { low: number; medium: number; high: number; unknown: number };
    approximatePenalty: number;
    unknownQualityPenalty: number;
    presumptivePenalty: number;
    stalePenalty: number;
    sourceBonus: number;
    maximumExtraSources: number;
  };
  limits: {
    maxPredictionSeconds: number;
    sampleSeconds: number;
    freshSeconds: number;
    staleSeconds: number;
    maxSpeedKmh: number;
    futureClockSkewSeconds: number;
    proximityRangeKm: number;
    minimumApproachKm: number;
    maxApproachHeadingError: number;
  };
  uncertainty: {
    minimumKm: number;
    driftKmPerMinute: number;
    approximateMultiplier: number;
    presumptiveMultiplier: number;
    maximumStrongUncertaintyKm: number;
  };
  thresholds: {
    WATCH: { enter: number; exit: number };
    WARNING: { enter: number; exit: number };
    HIGH: { enter: number; exit: number };
  };
  hysteresis: {
    entryCycles: number;
    exitCycles: number;
    resolutionGraceSeconds: number;
    reminderCooldownSeconds: number;
    minimumNotificationGapSeconds: number;
    notifyWatch: boolean;
  };
}

/** Initial calibration values; they are not weapon-performance facts or validated guarantees. */
export const DEFAULT_ENGINE_CONFIG: Readonly<EngineConfig> = {
  version: "obriy-initial-1",
  weights: {
    evidence: 0.2,
    freshness: 0.1,
    proximity: 0.15,
    approaching: 0.2,
    corridorHit: 0.3,
    officialContext: 0.05,
  },
  evidence: {
    base: { low: 0.35, medium: 0.6, high: 0.8, unknown: 0.3 },
    approximatePenalty: 0.15,
    unknownQualityPenalty: 0.25,
    presumptivePenalty: 0.1,
    stalePenalty: 0.3,
    sourceBonus: 0.03,
    maximumExtraSources: 4,
  },
  limits: {
    maxPredictionSeconds: 600,
    sampleSeconds: 15,
    freshSeconds: 60,
    staleSeconds: 600,
    maxSpeedKmh: 15000,
    futureClockSkewSeconds: 30,
    proximityRangeKm: 100,
    minimumApproachKm: 0.25,
    maxApproachHeadingError: 75,
  },
  uncertainty: {
    minimumKm: 2,
    driftKmPerMinute: 0.5,
    approximateMultiplier: 2,
    presumptiveMultiplier: 1.5,
    maximumStrongUncertaintyKm: 15,
  },
  thresholds: {
    WATCH: { enter: 45, exit: 30 },
    WARNING: { enter: 65, exit: 50 },
    HIGH: { enter: 80, exit: 65 },
  },
  hysteresis: {
    entryCycles: 2,
    exitCycles: 3,
    resolutionGraceSeconds: 60,
    reminderCooldownSeconds: 900,
    minimumNotificationGapSeconds: 60,
    notifyWatch: false,
  },
};
