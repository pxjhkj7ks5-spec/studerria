import type { Point } from "./types.js";

export const EARTH_RADIUS_KM = 6371.0088;
const toRadians = (n: number) => (n * Math.PI) / 180;
const toDegrees = (n: number) => (n * 180) / Math.PI;
export const clamp = (value: number, min = 0, max = 1): number =>
  Math.max(min, Math.min(max, value));
export function validPoint(point: Point): boolean {
  return (
    Number.isFinite(point.lat) &&
    Number.isFinite(point.lon) &&
    Math.abs(point.lat) <= 90 &&
    Math.abs(point.lon) <= 180
  );
}
function assertPoint(point: Point): void {
  if (!validPoint(point)) throw new Error("Invalid geographic point");
}
export function normalizeHeading(heading: number): number {
  return ((heading % 360) + 360) % 360;
}
export function angularDifference(a: number, b: number): number {
  return Math.abs(
    ((normalizeHeading(a) - normalizeHeading(b) + 540) % 360) - 180,
  );
}
export function haversineDistance(a: Point, b: Point): number {
  assertPoint(a);
  assertPoint(b);
  const dLat = toRadians(b.lat - a.lat);
  const dLon = toRadians(b.lon - a.lon);
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRadians(a.lat)) *
      Math.cos(toRadians(b.lat)) *
      Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_RADIUS_KM * Math.asin(Math.sqrt(clamp(h)));
}
export function initialBearing(a: Point, b: Point): number {
  assertPoint(a);
  assertPoint(b);
  const dLon = toRadians(b.lon - a.lon);
  const y = Math.sin(dLon) * Math.cos(toRadians(b.lat));
  const x =
    Math.cos(toRadians(a.lat)) * Math.sin(toRadians(b.lat)) -
    Math.sin(toRadians(a.lat)) * Math.cos(toRadians(b.lat)) * Math.cos(dLon);
  return normalizeHeading(toDegrees(Math.atan2(y, x)));
}
export function destinationPoint(
  start: Point,
  bearingDeg: number,
  distanceKm: number,
): Point {
  assertPoint(start);
  if (
    !Number.isFinite(bearingDeg) ||
    !Number.isFinite(distanceKm) ||
    distanceKm < 0
  )
    throw new Error("Invalid geodesic motion");
  const phi1 = toRadians(start.lat),
    lambda1 = toRadians(start.lon),
    theta = toRadians(normalizeHeading(bearingDeg));
  const delta = distanceKm / EARTH_RADIUS_KM;
  const phi2 = Math.asin(
    clamp(
      Math.sin(phi1) * Math.cos(delta) +
        Math.cos(phi1) * Math.sin(delta) * Math.cos(theta),
      -1,
      1,
    ),
  );
  const lambda2 =
    lambda1 +
    Math.atan2(
      Math.sin(theta) * Math.sin(delta) * Math.cos(phi1),
      Math.cos(delta) - Math.sin(phi1) * Math.sin(phi2),
    );
  return {
    lat: toDegrees(phi2),
    lon: ((toDegrees(lambda2) + 540) % 360) - 180,
  };
}

const DISTANCE_BANDS = [
  "<10 км",
  "10–20 км",
  "20–30 км",
  "30–50 км",
  "50–75 км",
  "75–100 км",
  ">100 км",
] as const;
export function distanceBand(distanceKm: number): string {
  const thresholds = [10, 20, 30, 50, 75, 100];
  return (
    DISTANCE_BANDS[thresholds.findIndex((n) => distanceKm < n)] ??
    DISTANCE_BANDS[6]
  );
}
export function distanceBandRank(band: string | undefined): number {
  return band === undefined
    ? -1
    : DISTANCE_BANDS.indexOf(band as (typeof DISTANCE_BANDS)[number]);
}

/** An outward-rounded interval prevents uncertainty being hidden behind a narrow band. */
export function uncertainDistanceBand(
  distanceKm: number,
  uncertaintyKm: number,
): string {
  if (uncertaintyKm <= 2) return distanceBand(distanceKm);
  const lower = Math.max(0, Math.floor((distanceKm - uncertaintyKm) / 5) * 5);
  const upper = Math.ceil((distanceKm + uncertaintyKm) / 5) * 5;
  return `${lower}–${upper} км`;
}
