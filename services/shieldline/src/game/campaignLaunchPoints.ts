import type { Coordinates, LiveThreat, ThreatKind } from "../types/game";

export interface CampaignLaunchPoint {
  routeId: string;
  sectorLabel: string;
  position: Coordinates;
  threatKind: ThreatKind;
  activeTracks: number;
}

export function campaignLaunchPointsForThreats(threats: readonly LiveThreat[]): CampaignLaunchPoint[] {
  const points = new Map<string, CampaignLaunchPoint>();
  for (const threat of threats) {
    if (!threat.routeId) continue;
    const existing = points.get(threat.routeId);
    if (existing) {
      existing.activeTracks += 1;
      existing.threatKind = threat.kind;
      continue;
    }
    points.set(threat.routeId, {
      routeId: threat.routeId,
      sectorLabel: threat.launchSectorName?.split(" · ")[0] || "невідомий сектор",
      position: { ...threat.origin },
      threatKind: threat.kind,
      activeTracks: 1,
    });
  }
  return [...points.values()];
}
