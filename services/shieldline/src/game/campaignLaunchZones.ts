import type { CampaignRouteTemplate } from "../data/campaignPlan";
import type { LaunchSector, ThreatKind } from "../types/game";
import { pickWeightedSector, sectorSupportsThreat } from "./launchSystem.mjs";

type CampaignLaunchAxis = CampaignRouteTemplate["launchSector"];

export const campaignLaunchSectorIdsByAxis: Record<CampaignLaunchAxis, readonly string[]> = {
  N1: ["northwest_deep_a", "north_corridor_b", "north_deep_a", "north_corridor_a"],
  NE1: ["north_corridor_b", "north_deep_a", "north_corridor_a"],
  NW1: ["northwest_deep_a", "north_corridor_b"],
  E1: ["north_corridor_a", "east_tactical_a", "east_deep_b", "southeast_corridor_a", "long_range_air_a"],
  SE1: ["southeast_corridor_a", "southeast_coastal_a", "southeast_corridor_b", "southeast_corridor_c", "long_range_air_a", "long_range_air_b"],
  S1: ["southeast_corridor_b", "southeast_corridor_c", "sea_corridor_b", "sea_corridor_c", "sea_corridor_a", "south_drone_a", "south_drone_b", "south_mixed_a"],
  SW1: ["sea_corridor_c", "sea_corridor_a", "south_drone_a", "south_drone_b", "south_mixed_a"],
};

export function pickCampaignLaunchSector(
  sectors: readonly LaunchSector[],
  axis: CampaignLaunchAxis,
  threatKind: ThreatKind,
  random: () => number,
  preferredSectorIds: readonly string[] = [],
): LaunchSector {
  const exactIds = new Set(preferredSectorIds);
  const exact = sectors.filter((sector) => exactIds.has(sector.id) && sectorSupportsThreat(sector, threatKind));
  if (exact.length) return pickWeightedSector(exact, threatKind, random);
  const preferredIds = new Set(campaignLaunchSectorIdsByAxis[axis]);
  const preferred = sectors.filter((sector) => preferredIds.has(sector.id) && sectorSupportsThreat(sector, threatKind));
  const compatible = preferred.length ? preferred : sectors.filter((sector) => sectorSupportsThreat(sector, threatKind));
  return pickWeightedSector(compatible, threatKind, random);
}
