import type { Coordinates, LiveThreat } from "../types/game";

export type ThreatRouteVisual = "hidden" | "predicted" | "confirmed";

interface RouteSample {
  points: Coordinates[];
  segmentIndex: number;
  segmentRatio: number;
  position: Coordinates;
}

function clampProgress(progress: number) {
  return Math.min(1, Math.max(0, Number.isFinite(progress) ? progress : 0));
}

function routePoints(threat: Pick<LiveThreat, "origin" | "target" | "routeWaypoints">) {
  return threat.routeWaypoints && threat.routeWaypoints.length > 1
    ? threat.routeWaypoints
    : [threat.origin, threat.target];
}

function segmentLength(left: Coordinates, right: Coordinates) {
  const middleLatitude = (left.lat + right.lat) * Math.PI / 360;
  const latitude = (right.lat - left.lat) * 111;
  const longitude = (right.lng - left.lng) * 111 * Math.max(.35, Math.cos(middleLatitude));
  return Math.hypot(latitude, longitude);
}

function interpolate(left: Coordinates, right: Coordinates, ratio: number): Coordinates {
  return { lat: left.lat + (right.lat - left.lat) * ratio, lng: left.lng + (right.lng - left.lng) * ratio };
}

function sampleRoute(threat: Pick<LiveThreat, "origin" | "target" | "routeWaypoints">, progress: number): RouteSample {
  const points = routePoints(threat);
  const lengths = points.slice(1).map((point, index) => segmentLength(points[index], point));
  const totalLength = lengths.reduce((sum, length) => sum + length, 0);
  let remaining = totalLength * clampProgress(progress);
  let segmentIndex = 0;
  while (segmentIndex < lengths.length - 1 && remaining > lengths[segmentIndex]) {
    remaining -= lengths[segmentIndex];
    segmentIndex += 1;
  }
  const segmentRatio = lengths[segmentIndex] > 0 ? Math.min(1, remaining / lengths[segmentIndex]) : 0;
  return { points, segmentIndex, segmentRatio, position: interpolate(points[segmentIndex], points[segmentIndex + 1], segmentRatio) };
}

export function threatPositionAtProgress(threat: Pick<LiveThreat, "origin" | "target" | "routeWaypoints">, progress: number): Coordinates {
  return sampleRoute(threat, progress).position;
}

export function threatCourseAtProgress(threat: Pick<LiveThreat, "origin" | "target" | "routeWaypoints">, progress: number) {
  const sample = sampleRoute(threat, progress);
  const from = sample.position;
  const to = sample.points[Math.min(sample.points.length - 1, sample.segmentIndex + 1)];
  const fallbackFrom = sample.points[Math.max(0, sample.segmentIndex)];
  const bearingFrom = segmentLength(from, to) > .001 ? from : fallbackFrom;
  const lat1 = bearingFrom.lat * Math.PI / 180;
  const lat2 = to.lat * Math.PI / 180;
  const deltaLongitude = (to.lng - bearingFrom.lng) * Math.PI / 180;
  const y = Math.sin(deltaLongitude) * Math.cos(lat2);
  const x = Math.cos(lat1) * Math.sin(lat2) - Math.sin(lat1) * Math.cos(lat2) * Math.cos(deltaLongitude);
  return (Math.atan2(y, x) * 180 / Math.PI + 360) % 360;
}

export function threatRouteAtProgress(threat: Pick<LiveThreat, "origin" | "target" | "routeWaypoints">, progress: number, visual: ThreatRouteVisual): Coordinates[] {
  const sample = sampleRoute(threat, progress);
  const remaining = sample.points.slice(sample.segmentIndex + 1);
  if (visual === "confirmed") return [sample.position, ...remaining];
  if (threat.routeWaypoints?.length) return [sample.position, ...remaining.slice(0, 2)];
  return [sample.position, predictedRouteEndpoint(sample.position, threat.target)];
}

export function classifyThreatRoute(threat: Pick<LiveThreat, "revealed" | "confidence" | "status">, reducedQuality: boolean): ThreatRouteVisual {
  if (!threat.revealed) return "hidden";
  const confirmed = threat.status === "engaged" || threat.confidence >= 60;
  if (confirmed) return "confirmed";
  if (!reducedQuality && threat.confidence >= 35) return "predicted";
  return "hidden";
}

export function predictedRouteEndpoint(current: Coordinates, target: Coordinates, progress = 0.34): Coordinates {
  const safeProgress = Math.min(0.5, Math.max(0.18, progress));
  return {
    lat: current.lat + (target.lat - current.lat) * safeProgress,
    lng: current.lng + (target.lng - current.lng) * safeProgress,
  };
}

export function advanceVisualThreatProgress(previous: number, authoritative: number, speed: number, frameDeltaMs: number) {
  const safePrevious = Number.isFinite(previous) ? previous : authoritative;
  const safeAuthoritative = Math.min(1, Math.max(0, authoritative));
  const safeDelta = Math.min(100, Math.max(0, frameDeltaMs));
  const safeSpeed = Math.max(0, speed);
  const projected = Math.min(1, safePrevious + safeSpeed * safeDelta);
  const gap = safeAuthoritative - projected;
  if (gap <= 0) return projected;
  const snapThreshold = Math.max(.035, safeSpeed * 500);
  if (gap > snapThreshold) return safeAuthoritative;
  const correction = Math.min(gap, Math.max(safeSpeed * safeDelta * .35, safeDelta * .0000025));
  return Math.min(1, projected + correction);
}
