import { getControlOverlay } from "../data/controlZones";
import type { Coordinates, UnitKind } from "../types/game";

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
  return { allowed: true };
}
