import { launchSectorCategory } from "./launchSystem.mjs";
import type { LaunchSector, ThreatKind } from "../types/game";

export type LauncherVariant =
  | "drone-mobile"
  | "drone-field"
  | "ballistic-tactical-tel"
  | "ballistic-heavy-tel"
  | "cruise-ground"
  | "cruise-naval"
  | "cruise-air";

const seaSectorIds = new Set(["sevastopol_black_sea", "novorossiysk_black_sea", "black_sea_launch_box"]);
const deepBallisticSectorIds = new Set(["voronezh_deep_east", "astrakhan_air_corridor", "vologda_air_corridor"]);

function stableParity(value: string) {
  let hash = 0;
  for (const character of value) hash = (hash * 31 + character.charCodeAt(0)) >>> 0;
  return hash % 2;
}

function isDrone(kind: ThreatKind) {
  return ["drone", "decoy", "saturation", "geran2", "gerbera", "parodiya"].includes(kind);
}

function isBallistic(kind: ThreatKind) {
  return kind === "ballistic" || kind === "iskander";
}

export function launcherVariantForSector(sector: LaunchSector): LauncherVariant {
  const kind = sector.activeThreatKind;
  if (kind) {
    if (isDrone(kind)) return stableParity(sector.id) ? "drone-mobile" : "drone-field";
    if (kind === "kh101") return "cruise-air";
    if (kind === "kalibr" && seaSectorIds.has(sector.id)) return "cruise-naval";
    if (isBallistic(kind)) return deepBallisticSectorIds.has(sector.id) ? "ballistic-heavy-tel" : "ballistic-tactical-tel";
    return "cruise-ground";
  }

  const category = launchSectorCategory(sector);
  if (category === "drone") return stableParity(sector.id) ? "drone-mobile" : "drone-field";
  if (category === "ballistic") return deepBallisticSectorIds.has(sector.id) ? "ballistic-heavy-tel" : "ballistic-tactical-tel";
  if (seaSectorIds.has(sector.id)) return "cruise-naval";
  if (sector.threats.some((threat) => threat === "kh101" || threat === "kh555")) return "cruise-air";
  return "cruise-ground";
}
