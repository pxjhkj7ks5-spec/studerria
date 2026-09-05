import { DEFAULT_ENGINE_CONFIG, type EngineConfig } from "./config.js";
import {
  angularDifference,
  clamp,
  destinationPoint,
  haversineDistance,
  initialBearing,
  uncertainDistanceBand,
  validPoint,
} from "./geometry.js";
import { deterministicId } from "./normalize.js";
import type {
  ExplanationCode,
  NormalizedTrack,
  Point,
  RiskAssessment,
  RiskFactors,
  Zone,
} from "./types.js";

function coordinate(track: NormalizedTrack): Point | null {
  const { lat, lon, areaOnly } = track.position;
  if (areaOnly || lat == null || lon == null) return null;
  const point = { lat, lon };
  return validPoint(point) ? point : null;
}
export function motionUsable(
  track: NormalizedTrack,
  config: Readonly<EngineConfig> = DEFAULT_ENGINE_CONFIG,
): boolean {
  return (
    coordinate(track) !== null &&
    track.status === "active" &&
    !track.advisory &&
    track.position.quality !== "unknown" &&
    Number.isFinite(track.motion.headingDeg) &&
    Number.isFinite(track.motion.speedKmh) &&
    (track.motion.speedKmh ?? 0) > 0 &&
    (track.motion.speedKmh ?? Infinity) <= config.limits.maxSpeedKmh &&
    !!track.motion.confirmedAt &&
    Number.isFinite(Date.parse(track.motion.confirmedAt))
  );
}

export function extrapolate(
  track: NormalizedTrack,
  at: Date,
  maxPredictionSeconds = DEFAULT_ENGINE_CONFIG.limits.maxPredictionSeconds,
): Point | null {
  if (
    !motionUsable(track) ||
    !Number.isFinite(at.getTime()) ||
    !Number.isFinite(maxPredictionSeconds) ||
    maxPredictionSeconds <= 0
  )
    return null;
  const start = coordinate(track);
  const ageSeconds =
    (at.getTime() - Date.parse(track.motion.confirmedAt!)) / 1000;
  if (!start || ageSeconds < 0) return null;
  const seconds = Math.min(ageSeconds, maxPredictionSeconds, 600);
  return destinationPoint(
    start,
    track.motion.headingDeg!,
    (track.motion.speedKmh! * seconds) / 3600,
  );
}

export function uncertaintyAt(
  track: NormalizedTrack,
  seconds: number,
  config: Readonly<EngineConfig> = DEFAULT_ENGINE_CONFIG,
): number | undefined {
  if (track.position.areaOnly || !coordinate(track)) return undefined;
  const base = Math.max(
    track.position.uncertaintyKm ?? 0,
    config.uncertainty.minimumKm,
  );
  let drift = config.uncertainty.driftKmPerMinute;
  if (track.position.quality !== "confirmed")
    drift *= config.uncertainty.approximateMultiplier;
  if (track.motion.presumptive)
    drift *= config.uncertainty.presumptiveMultiplier;
  return Math.hypot(base, (drift * Math.max(0, seconds)) / 60);
}
export function evidenceScore(
  track: NormalizedTrack,
  config: Readonly<EngineConfig> = DEFAULT_ENGINE_CONFIG,
): number {
  const values = config.evidence;
  let evidence =
    values.base[track.confidence.upstreamLevel] ?? values.base.unknown;
  if (track.position.quality === "approx")
    evidence -= values.approximatePenalty;
  if (track.position.quality === "unknown")
    evidence -= values.unknownQualityPenalty;
  if (track.motion.presumptive) evidence -= values.presumptivePenalty;
  if (track.status === "stale") evidence -= values.stalePenalty;
  const extraSources = clamp(
    (track.confidence.sourceCount ?? 1) - 1,
    0,
    values.maximumExtraSources,
  );
  return clamp(evidence + extraSources * values.sourceBonus);
}
export function riskScore(
  factors: RiskFactors,
  config: Readonly<EngineConfig> = DEFAULT_ENGINE_CONFIG,
): number {
  const terms = Object.keys(factors) as (keyof RiskFactors)[];
  return (
    Math.round(
      clamp(
        terms.reduce(
          (sum, key) => sum + config.weights[key] * clamp(factors[key]),
          0,
        ),
      ) * 10000,
    ) / 100
  );
}

export function assess(
  track: NormalizedTrack,
  zone: Zone,
  now: Date,
  officialActive: boolean,
  config: Readonly<EngineConfig> = DEFAULT_ENGINE_CONFIG,
): RiskAssessment {
  if (
    !validPoint(zone) ||
    !Number.isFinite(zone.radiusKm) ||
    zone.radiusKm <= 0 ||
    zone.radiusKm > 500 ||
    !Number.isFinite(now.getTime())
  )
    throw new Error("Invalid assessment inputs");
  const observedMs = Date.parse(track.observedAt);
  const updatedMs = Date.parse(track.updatedAt);
  if (
    !Number.isFinite(observedMs) ||
    !Number.isFinite(updatedMs) ||
    observedMs > now.getTime() + config.limits.futureClockSkewSeconds * 1000
  )
    throw new Error("Invalid assessment timestamp");
  if (
    track.motion.confirmedAt &&
    (!Number.isFinite(Date.parse(track.motion.confirmedAt)) ||
      Date.parse(track.motion.confirmedAt) > now.getTime())
  )
    throw new Error("Invalid motion timestamp");
  const ageSeconds = Math.max(0, (now.getTime() - observedMs) / 1000);
  const stale =
    track.status === "stale" || ageSeconds >= config.limits.staleSeconds;
  const resolved = track.status === "resolved";
  const explanationCodes: ExplanationCode[] = [];
  if (track.position.areaOnly) explanationCodes.push("AREA_ONLY");
  if (track.advisory) explanationCodes.push("ADVISORY");
  if (stale) explanationCodes.push("STALE");
  if (resolved) explanationCodes.push("SOURCE_RESOLVED");
  if (track.status === "unknown")
    explanationCodes.push("SOURCE_STATUS_UNKNOWN");
  if (!zone.enabled) explanationCodes.push("ZONE_DISABLED");
  if (officialActive) explanationCodes.push("OFFICIAL_ALERT_ACTIVE");
  if (track.confidence.upstreamLevel === "high")
    explanationCodes.push("HIGH_UPSTREAM_CONFIDENCE");
  if (track.position.quality !== "confirmed")
    explanationCodes.push("LOW_POSITION_QUALITY");

  const position = coordinate(track);
  if (!position && !track.position.areaOnly)
    explanationCodes.push("POSITION_UNAVAILABLE");
  const hasMotion = motionUsable(track, config) && !stale && !resolved;
  if (!hasMotion) explanationCodes.push("INSUFFICIENT_MOTION");
  const maxHorizon = Math.max(
    0,
    Math.min(600, config.limits.maxPredictionSeconds),
  );
  const motionAge = track.motion.confirmedAt
    ? Math.max(0, (now.getTime() - Date.parse(track.motion.confirmedAt)) / 1000)
    : 0;
  const horizonSeconds = hasMotion ? Math.max(0, maxHorizon - motionAge) : 0;
  if (hasMotion && horizonSeconds === 0)
    explanationCodes.push("PREDICTION_HORIZON_EXHAUSTED");
  const canForecast = hasMotion && horizonSeconds > 0;
  const currentPosition = canForecast
    ? (extrapolate(track, now, maxHorizon) ?? position)
    : position;
  const geometry: RiskAssessment["geometry"] = { corridorIntersects: false };
  let approaching = 0;
  let strongIntersection = false;
  let corridorContribution = 0;
  if (currentPosition) {
    const distance = haversineDistance(currentPosition, zone);
    const uncertainty =
      uncertaintyAt(track, ageSeconds, config) ?? config.uncertainty.minimumKm;
    geometry.currentDistanceKm = distance;
    geometry.uncertaintyKm = uncertainty;
    geometry.distanceBand = uncertainDistanceBand(distance, uncertainty);
    geometry.distanceTrend = "unknown";
    if (canForecast) {
      const bearing = initialBearing(currentPosition, zone);
      const headingError = angularDifference(track.motion.headingDeg!, bearing);
      geometry.bearingToZone = bearing;
      geometry.headingError = headingError;
      geometry.forecastHorizonSeconds = horizonSeconds;
      let minimumDistance = distance;
      const step = Math.max(1, Math.min(60, config.limits.sampleSeconds));
      let firstHitSeconds: number | undefined;
      let firstHitUncertainty = uncertainty;
      let nominalIntersects = false;
      // The horizon is measured from the source anchor, never renewed by aging ticks.
      const sampleTimes = [0];
      for (let seconds = step; seconds < horizonSeconds; seconds += step)
        sampleTimes.push(seconds);
      sampleTimes.push(horizonSeconds);
      for (const seconds of sampleTimes) {
        const predicted = extrapolate(
          track,
          new Date(now.getTime() + seconds * 1000),
          maxHorizon,
        );
        if (!predicted) continue;
        const predictedDistance = haversineDistance(predicted, zone);
        const predictedUncertainty = uncertaintyAt(
          track,
          motionAge + seconds,
          config,
        )!;
        minimumDistance = Math.min(minimumDistance, predictedDistance);
        nominalIntersects ||= predictedDistance <= zone.radiusKm;
        if (
          predictedDistance <= zone.radiusKm + predictedUncertainty &&
          firstHitSeconds === undefined
        ) {
          firstHitSeconds = seconds;
          firstHitUncertainty = predictedUncertainty;
        }
      }
      const next = extrapolate(
        track,
        new Date(now.getTime() + Math.min(60, horizonSeconds) * 1000),
        maxHorizon,
      )!;
      const change = distance - haversineDistance(next, zone);
      const isApproaching =
        change >= config.limits.minimumApproachKm &&
        headingError <= config.limits.maxApproachHeadingError;
      approaching = isApproaching
        ? clamp(Math.cos((headingError * Math.PI) / 180))
        : 0;
      geometry.distanceTrend = isApproaching
        ? "approaching"
        : change < -config.limits.minimumApproachKm
          ? "receding"
          : "steady";
      geometry.minimumPredictedDistanceKm = minimumDistance;
      geometry.corridorIntersects = firstHitSeconds !== undefined;
      if (firstHitSeconds !== undefined) {
        geometry.firstPossibleCorridorEntry = {
          fromSeconds: Math.max(0, firstHitSeconds - step),
          toSeconds: firstHitSeconds,
        };
        explanationCodes.push("CORRIDOR_INTERSECTION");
        strongIntersection =
          (nominalIntersects || distance <= zone.radiusKm + uncertainty) &&
          firstHitUncertainty <= config.uncertainty.maximumStrongUncertaintyKm;
        corridorContribution = strongIntersection ? 1 : 0.65;
      }
      geometry.strongCorridorIntersection = strongIntersection;
      if (isApproaching) explanationCodes.push("APPROACHING");
      if (geometry.distanceTrend === "receding")
        explanationCodes.push("TURNING_AWAY");
      if (!geometry.corridorIntersects) explanationCodes.push("NEAR_MISS");
      if (firstHitUncertainty > config.uncertainty.maximumStrongUncertaintyKm)
        explanationCodes.push("UNCERTAINTY_DOMINATES");
    }
  }
  const freshness =
    stale || resolved
      ? 0
      : clamp(
          1 -
            Math.max(0, ageSeconds - config.limits.freshSeconds) /
              Math.max(
                1,
                config.limits.staleSeconds - config.limits.freshSeconds,
              ),
        );
  const factors: RiskFactors = {
    evidence: evidenceScore(track, config),
    freshness,
    proximity:
      geometry.currentDistanceKm === undefined
        ? 0
        : clamp(
            1 -
              Math.max(0, geometry.currentDistanceKm - zone.radiusKm) /
                config.limits.proximityRangeKm,
          ),
    approaching,
    corridorHit: corridorContribution,
    officialContext: officialActive ? 1 : 0,
  };
  const score = riskScore(factors, config);
  const escalationAllowed =
    zone.enabled &&
    !track.advisory &&
    !track.position.areaOnly &&
    !stale &&
    !resolved &&
    track.status === "active" &&
    !!position;
  let level: RiskAssessment["level"] = "INFO";
  if (escalationAllowed && canForecast) {
    if (score >= config.thresholds.WATCH.enter) level = "WATCH";
    if (
      score >= config.thresholds.WARNING.enter &&
      geometry.corridorIntersects &&
      approaching > 0
    )
      level = "WARNING";
    if (
      score >= config.thresholds.HIGH.enter &&
      strongIntersection &&
      (approaching > 0 ||
        (geometry.currentDistanceKm ?? Infinity) <= zone.radiusKm)
    )
      level = "HIGH";
  }
  return {
    version: "1",
    assessmentId: deterministicId(
      JSON.stringify([
        track.internalId,
        track.updatedAt,
        zone.id,
        now.toISOString(),
        config.version,
        officialActive,
        score,
        geometry,
        explanationCodes,
      ]),
    ),
    trackId: track.internalId,
    zoneId: zone.id,
    evaluatedAt: now.toISOString(),
    sourceUpdatedAt: track.updatedAt,
    level,
    score,
    factors,
    geometry,
    explanationCodes,
    engineConfigVersion: config.version,
    escalationAllowed,
    resolved,
  };
}
