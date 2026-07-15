import type { Coordinates, LiveThreat } from "../types/game";

export type ThreatRouteVisual = "hidden" | "predicted" | "confirmed";

export function classifyThreatRoute(threat: Pick<LiveThreat, "revealed" | "confidence" | "status">, reducedQuality: boolean): ThreatRouteVisual {
  if (!threat.revealed) return "hidden";
  const confirmed = threat.status === "engaged" || threat.confidence >= 58;
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
