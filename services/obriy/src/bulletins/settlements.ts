import { readFileSync } from "node:fs";
import path from "node:path";
import { haversineDistance } from "../engine/geometry.js";
import type { Point } from "../engine/types.js";
import { AREAS, type BulletinArea } from "./areas.js";

export interface Settlement extends BulletinArea, Point {
  admin: string;
}
export const SETTLEMENTS: Settlement[] = JSON.parse(
  readFileSync(path.resolve("data/settlements.json"), "utf8"),
);
// Limited explicit inflections; no fuzzy matching over the nationwide gazetteer.
for (const place of SETTLEMENTS) {
  const known = AREAS.find((a) =>
    place.aliases.includes(a.label.toLocaleLowerCase("uk")),
  );
  const aliases = new Set([...place.aliases, ...(known?.aliases ?? [])]);
  if (known?.parent && place.admin === "13") place.parent = known.parent;
  for (const name of place.aliases) {
    if (/[бвгґджзклмнпрстфхцчшщ]$/u.test(name))
      for (const suffix of ["а", "у", "і", "ом"]) aliases.add(name + suffix);
  }
  place.aliases = [...aliases];
  if (!place.parent && place.admin === "13") place.parent = "kyiv-oblast";
}
export function nearbySettlements(point: Point, radiusKm: number) {
  return SETTLEMENTS.filter(
    (p) => Math.abs(p.lat - point.lat) <= radiusKm / 110,
  )
    .map((p) => ({ ...p, distanceKm: haversineDistance(point, p) }))
    .filter((p) => p.distanceKm <= radiusKm)
    .sort((a, b) => a.distanceKm - b.distanceKm);
}
export function zoneAreas(
  zone: Point & {
    radiusKm: number;
    bulletinRadius?: boolean;
    bulletinAreas?: string[];
  },
) {
  return [
    ...AREAS.filter((a) => (zone.bulletinAreas ?? []).includes(a.id)),
    ...(zone.bulletinRadius !== false
      ? nearbySettlements(zone, zone.radiusKm)
      : []),
  ];
}
export function areaLabel(id: string) {
  return id === "ballistic-general"
    ? "Загальне попередження про балістику / ОТРК"
    : (AREAS.find((a) => a.id === id)?.label ??
        SETTLEMENTS.find((a) => a.id === id)?.label ??
        id);
}
