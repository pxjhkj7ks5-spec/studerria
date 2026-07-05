import { getControlOverlay } from "../data/controlZones";
import type { Coordinates, UnitKind } from "../types/game";

export const MIN_FRONT_DISTANCE_KM = 10;
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

export function pointInPolygon(point: Coordinates, polygon: Coordinates[]) {
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

export function projectDistanceKm(point: Coordinates, start: Coordinates, end: Coordinates) {
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

export function minDistanceToLineKm(point: Coordinates, line: Coordinates[]) {
  let min = Number.POSITIVE_INFINITY;
  for (let index = 1; index < line.length; index += 1) {
    min = Math.min(min, projectDistanceKm(point, line[index - 1], line[index]));
  }
  return min;
}

export function createLineBufferPolygons(line: Coordinates[], bufferKm = MIN_FRONT_DISTANCE_KM) {
  const polygons: Coordinates[][] = [];
  for (let index = 1; index < line.length; index += 1) {
    const start = line[index - 1];
    const end = line[index];
    const avgLat = toRad((start.lat + end.lat) / 2);
    const latKm = 110.57;
    const lngKm = Math.max(1, Math.cos(avgLat) * 111.32);
    const dx = (end.lng - start.lng) * lngKm;
    const dy = (end.lat - start.lat) * latKm;
    const length = Math.hypot(dx, dy);
    if (!length) continue;
    const offsetLat = (dx / length) * (bufferKm / latKm);
    const offsetLng = (-dy / length) * (bufferKm / lngKm);
    polygons.push([
      { lat: start.lat + offsetLat, lng: start.lng + offsetLng },
      { lat: end.lat + offsetLat, lng: end.lng + offsetLng },
      { lat: end.lat - offsetLat, lng: end.lng - offsetLng },
      { lat: start.lat - offsetLat, lng: start.lng - offsetLng },
    ]);
  }
  return polygons;
}

export function validateBatteryPlacement(kind: UnitKind, position: Coordinates): { allowed: boolean; reason?: string } {
  const overlay = getControlOverlay();

  if (kind === "boat") {
    const onWater = overlay.waterPlacementPolygons.some((polygon) => pointInPolygon(position, polygon));
    return onWater
      ? { allowed: true }
      : { allowed: false, reason: "Boats can be placed only on water areas." };
  }

  if (!pointInPolygon(position, overlay.ukrainePlacementPolygon)) {
    return { allowed: false, reason: "PPO placement is allowed only inside Ukraine." };
  }
  const insideOccupied = overlay.occupiedPolygons.some((polygon) => pointInPolygon(position, polygon));
  if (insideOccupied) {
    return { allowed: false, reason: "Placement is blocked inside occupied territory." };
  }
  const frontierDistance = minDistanceToLineKm(position, overlay.frontline);
  if (frontierDistance < MIN_FRONT_DISTANCE_KM) {
    return { allowed: false, reason: "Placement must be at least 10 km from the configured front line." };
  }
  return { allowed: true };
}
