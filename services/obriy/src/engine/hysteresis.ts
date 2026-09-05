import { DEFAULT_ENGINE_CONFIG, type EngineConfig } from "./config.js";
import { distanceBand, distanceBandRank } from "./geometry.js";
import type { AlertLevel, AlertState, RiskAssessment } from "./types.js";

const levelRank: Record<AlertLevel, number> = {
  INFO: 0,
  WATCH: 1,
  WARNING: 2,
  HIGH: 3,
  RESOLVED: 0,
};
export interface TransitionOptions {
  now?: Date;
  eventKey?: string;
  config?: Readonly<EngineConfig>;
}

export function transition(
  previous: AlertState | null,
  assessment: RiskAssessment,
  options: TransitionOptions = {},
): { state: AlertState; notify: boolean; reason?: string } {
  const config = options.config ?? DEFAULT_ENGINE_CONFIG;
  const now = options.now ?? new Date(assessment.evaluatedAt);
  if (!Number.isFinite(now.getTime()))
    throw new Error("Invalid transition clock");
  const eventKey = options.eventKey ?? assessment.assessmentId;
  if (
    previous?.recentEventKeys?.includes(eventKey) ||
    previous?.lastEventKey === eventKey
  )
    return { state: previous, notify: false, reason: "DUPLICATE_EVENT" };
  const sourceTimestamp = Date.parse(assessment.sourceUpdatedAt);
  const previousTimestamp = previous?.lastSourceUpdatedAt
    ? Date.parse(previous.lastSourceUpdatedAt)
    : -Infinity;
  if (!Number.isFinite(sourceTimestamp))
    throw new Error("Invalid transition source timestamp");
  if (
    sourceTimestamp < previousTimestamp ||
    (previous?.lastEvaluatedAt &&
      now.getTime() < Date.parse(previous.lastEvaluatedAt))
  )
    return { state: previous!, notify: false, reason: "OUT_OF_ORDER_EVENT" };
  const freshSourceEvidence = sourceTimestamp > previousTimestamp;
  const state: AlertState = {
    currentLevel: previous?.currentLevel ?? "INFO",
    consecutiveAbove: previous?.consecutiveAbove ?? 0,
    consecutiveBelow: previous?.consecutiveBelow ?? 0,
    ...previous,
    lastScore: assessment.score,
    recentEventKeys: [...(previous?.recentEventKeys ?? []), eventKey].slice(
      -32,
    ),
    lastEventKey: eventKey,
    lastSourceUpdatedAt: assessment.sourceUpdatedAt,
    lastEvaluatedAt: now.toISOString(),
  };
  const priorLevel = state.currentLevel;
  const forcedInfo = assessment.explanationCodes.some((code) =>
    [
      "AREA_ONLY",
      "ADVISORY",
      "ZONE_DISABLED",
      "SOURCE_STATUS_UNKNOWN",
      "POSITION_UNAVAILABLE",
    ].includes(code),
  );

  if (assessment.resolved) {
    state.resolvedAt ??= now.toISOString();
    if (
      now.getTime() - Date.parse(state.resolvedAt) >=
      config.hysteresis.resolutionGraceSeconds * 1000
    ) {
      state.currentLevel = "RESOLVED";
      state.consecutiveAbove = 0;
      state.consecutiveBelow = 0;
      state.pendingLevel = undefined;
      if (
        previous?.currentLevel !== "RESOLVED" &&
        state.hadHighLevelNotification
      ) {
        state.lastNotificationAt = now.toISOString();
        state.lastNotifiedLevel = "RESOLVED";
        return { state, notify: true, reason: "SOURCE_RESOLVED_AFTER_WARNING" };
      }
    }
    return { state, notify: false, reason: "SOURCE_RESOLUTION_GRACE" };
  }
  state.resolvedAt = undefined;
  if (state.currentLevel === "RESOLVED") {
    state.currentLevel = "INFO";
    state.consecutiveAbove = 0;
    state.consecutiveBelow = 0;
    state.pendingLevel = undefined;
    state.hadHighLevelNotification = false;
  }
  if (forcedInfo) {
    state.currentLevel = "INFO";
    state.consecutiveAbove = 0;
    state.consecutiveBelow = 0;
    state.pendingLevel = undefined;
  } else if (
    assessment.escalationAllowed &&
    freshSourceEvidence &&
    levelRank[assessment.level] > levelRank[state.currentLevel]
  ) {
    // Entering a stronger candidate keeps earlier evidence only if it met that threshold too.
    state.consecutiveAbove =
      state.pendingLevel === assessment.level ? state.consecutiveAbove + 1 : 1;
    state.pendingLevel = assessment.level;
    state.consecutiveBelow = 0;
    if (state.consecutiveAbove >= config.hysteresis.entryCycles) {
      state.currentLevel = assessment.level;
      state.consecutiveAbove = 0;
      state.pendingLevel = undefined;
    }
  } else {
    if (freshSourceEvidence || !assessment.escalationAllowed) {
      state.consecutiveAbove = 0;
      state.pendingLevel = undefined;
    }
    const currentThreshold =
      state.currentLevel === "INFO"
        ? null
        : config.thresholds[state.currentLevel];
    const safetyLoss =
      !assessment.escalationAllowed ||
      assessment.explanationCodes.includes("INSUFFICIENT_MOTION");
    if (
      currentThreshold &&
      (assessment.score < currentThreshold.exit ||
        safetyLoss ||
        (state.currentLevel === "HIGH" &&
          !assessment.geometry.strongCorridorIntersection) ||
        (state.currentLevel === "WARNING" &&
          assessment.factors.approaching === 0))
    ) {
      state.consecutiveBelow += 1;
      if (state.consecutiveBelow >= config.hysteresis.exitCycles) {
        state.currentLevel =
          levelRank[assessment.level] < levelRank[state.currentLevel]
            ? assessment.level
            : "INFO";
        state.consecutiveBelow = 0;
      }
    } else state.consecutiveBelow = 0;
  }

  const approaching = assessment.factors.approaching > 0;
  const bandRank =
    assessment.geometry.currentDistanceKm === undefined
      ? -1
      : distanceBandRank(distanceBand(assessment.geometry.currentDistanceKm));
  const levelIncreased = levelRank[state.currentLevel] > levelRank[priorLevel];
  const eligible =
    assessment.escalationAllowed &&
    !forcedInfo &&
    freshSourceEvidence &&
    (state.currentLevel === "WARNING" ||
      state.currentLevel === "HIGH" ||
      (config.hysteresis.notifyWatch && state.currentLevel === "WATCH")) &&
    levelRank[assessment.level] >= levelRank[state.currentLevel];
  const sinceNotification = state.lastNotificationAt
    ? (now.getTime() - Date.parse(state.lastNotificationAt)) / 1000
    : Infinity;
  const closerBand =
    bandRank >= 0 &&
    (state.lastNotifiedDistanceBandRank ?? -1) >= 0 &&
    bandRank < state.lastNotifiedDistanceBandRank!;
  const changedApproach = approaching && previous?.lastApproaching === false;
  const changedCorridor =
    assessment.geometry.corridorIntersects &&
    previous?.lastCorridorIntersects === false;
  const cooldown =
    sinceNotification >= config.hysteresis.reminderCooldownSeconds;
  const materialChange =
    closerBand || changedApproach || changedCorridor || cooldown;
  const notify =
    eligible &&
    (levelIncreased ||
      (materialChange &&
        sinceNotification >= config.hysteresis.minimumNotificationGapSeconds));
  state.lastApproaching = approaching;
  state.lastCorridorIntersects = assessment.geometry.corridorIntersects;
  state.lastDistanceBand = assessment.geometry.distanceBand;
  state.lastDistanceBandRank = bandRank;
  if (notify) {
    state.lastNotificationAt = now.toISOString();
    state.lastNotifiedLevel = state.currentLevel;
    state.lastNotifiedDistanceBandRank = bandRank;
    if (state.currentLevel === "WARNING" || state.currentLevel === "HIGH")
      state.hadHighLevelNotification = true;
  }
  return {
    state,
    notify,
    reason: notify
      ? levelIncreased
        ? "LEVEL_INCREASED"
        : closerBand
          ? "CLOSER_DISTANCE_BAND"
          : changedApproach
            ? "APPROACHING_CHANGED"
            : changedCorridor
              ? "CORRIDOR_CHANGED"
              : "REMINDER_COOLDOWN"
      : undefined,
  };
}
