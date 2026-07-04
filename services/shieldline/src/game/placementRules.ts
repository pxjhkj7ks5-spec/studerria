import { controlOverlay } from "../data/controlZones";
import type { Coordinates } from "../types/game";

const MIN_FRONT_DISTANCE_KM = 15;
const EARTH_RADIUS_KM = 6371;

function toRad(value: number) {
  return (value * Math.PI) / 180;
}

export function distanceKm(left: Coordinates, right: Coordinates) {
  const dLat = toRad(right.lat - left.lat);
  const dLng = toRad(right.lng - left.lng);
  const lat1 = toRad(left.lat);
  const lat2 = toRad(right.lat);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLng / 2) ** 2;
  return 2 * EARTH_RADIUS_KM * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

function pointInPolygon(point: Coordinates, polygon: Coordinates[]) {
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const xi = polygon[i].lng;
    const yi = polygon[i].lat;
    const xj = polygon[j].lng;
    const yj = polygon[j].lat;
    const intersects = yi > point.lat !== yj > point.lat
      && point.lng < ((xj - xi) * (point.lat - yi)) / (yj - yi || 0.000001) + xi;
    if (intersects) inside = !inside;
  }
  return inside;
}

function projectDistanceKm(point: Coordinates, start: Coordinates, end: Coordinates) {
  const avgLat = toRad((start.lat + end.lat + point.lat) / 3);
  const scaleLng = Math.cos(avgLat) * 111.32;
  const toXY = (coord: Coordinates) => ({ x: coord.lng * scaleLng, y: coord.lat * 110.57 });
  const p = toXY(point);
  const a = toXY(start);
  const b = toXY(end);
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const lenSq = dx * dx + dy * dy;
  if (!lenSq) return Math.hypot(p.x - a.x, p.y - a.y);
  const t = Math.max(0, Math.min(1, ((p.x - a.x) * dx + (p.y - a.y) * dy) / lenSq));
  return Math.hypot(p.x - (a.x + t * dx), p.y - (a.y + t * dy));
}

function minDistanceToLineKm(point: Coordinates, line: Coordinates[]) {
  let min = Number.POSITIVE_INFINITY;
  for (let index = 1; index < line.length; index += 1) {
    min = Math.min(min, projectDistanceKm(point, line[index - 1], line[index]));
  }
  return min;
}

export function validateBatteryPlacement(position: Coordinates): { allowed: boolean; reason?: string } {
  if (!pointInPolygon(position, controlOverlay.controlledUkrainePolygon)) {
    return { allowed: false, reason: "Placement is allowed only on controlled Ukrainian territory." };
  }
  const insideOccupied = controlOverlay.temporarilyOccupiedPolygons.some((polygon) => pointInPolygon(position, polygon));
  if (insideOccupied) {
    return { allowed: false, reason: "Placement is blocked inside contested or occupied game zones." };
  }
  const frontierDistance = Math.min(
    minDistanceToLineKm(position, controlOverlay.frontline),
    minDistanceToLineKm(position, controlOverlay.hostileBorder),
  );
  if (frontierDistance < MIN_FRONT_DISTANCE_KM) {
    return { allowed: false, reason: "Placement must be at least 15 km from the front or hostile border." };
  }
  return { allowed: true };
}
