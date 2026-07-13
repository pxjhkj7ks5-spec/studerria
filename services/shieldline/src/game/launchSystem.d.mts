import type { Coordinates, LaunchSector, LaunchThreatProfile, ThreatKind } from "../types/game";

export const SHOW_LAUNCH_DEBUG: boolean;
export const launchSectors: readonly LaunchSector[];
export const FIRST_NIGHT_LAUNCH_SECTOR_IDS: readonly string[];
export const SECOND_NIGHT_LAUNCH_SECTOR_IDS: readonly string[];
export const ALL_LAUNCH_SECTOR_IDS: readonly string[];
export const CAMPAIGN_RANDOM_LAUNCH_SECTOR_IDS: readonly string[];
export function threatProfilesForKind(kind: ThreatKind | string): LaunchThreatProfile[];
export function sectorSupportsThreat(sector: LaunchSector, threatType: ThreatKind | string | null): boolean;
export function createLaunchSectorState(ids?: readonly string[]): LaunchSector[];
export function pickWeightedSector(sectors: readonly LaunchSector[], allowedThreatType?: ThreatKind | string | null, random?: () => number): LaunchSector;
export function randomPointInSector(sector: LaunchSector, random?: () => number): Coordinates;
export function generateLaunchOrigin(sectors: readonly LaunchSector[], threatType: ThreatKind | string, random?: () => number): { sector: LaunchSector; point: Coordinates };
export function launchSectorCategory(sector: LaunchSector): "drone" | "ballistic" | "cruise";
export function launchSectorCenter(sector: LaunchSector): Coordinates;
