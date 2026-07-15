import type { CampaignRouteTemplate } from "../data/campaignPlan";
import type { LaunchSector, ThreatKind } from "../types/game";
import { pickWeightedSector, sectorSupportsThreat } from "./launchSystem.mjs";

type CampaignLaunchAxis = CampaignRouteTemplate["launchSector"];

export const campaignLaunchSectorIdsByAxis: Record<CampaignLaunchAxis, readonly string[]> = {
  N1: ["smolensk_northwest", "bryansk_north", "oryol_deep_north", "kursk_north"],
  NE1: ["bryansk_north", "oryol_deep_north", "kursk_north"],
  NW1: ["smolensk_northwest", "bryansk_north"],
  E1: ["kursk_north", "belgorod_tactical", "voronezh_deep_east", "millerovo_rostov", "astrakhan_air_corridor"],
  SE1: ["millerovo_rostov", "taganrog_azov", "primorsko_akhtarsk", "yeisk_kuban", "astrakhan_air_corridor"],
  S1: ["primorsko_akhtarsk", "yeisk_kuban", "novorossiysk_black_sea", "black_sea_launch_box", "sevastopol_black_sea", "hvardiiske_crimea", "chauda_crimea", "dzhankoi_crimea"],
  SW1: ["black_sea_launch_box", "sevastopol_black_sea", "hvardiiske_crimea", "chauda_crimea", "dzhankoi_crimea"],
};

export function pickCampaignLaunchSector(
  sectors: readonly LaunchSector[],
  axis: CampaignLaunchAxis,
  threatKind: ThreatKind,
  random: () => number,
): LaunchSector {
  const preferredIds = new Set(campaignLaunchSectorIdsByAxis[axis]);
  const preferred = sectors.filter((sector) => preferredIds.has(sector.id) && sectorSupportsThreat(sector, threatKind));
  const compatible = preferred.length ? preferred : sectors.filter((sector) => sectorSupportsThreat(sector, threatKind));
  return pickWeightedSector(compatible, threatKind, random);
}
