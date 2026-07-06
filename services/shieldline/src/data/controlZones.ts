import type { Coordinates } from "../types/game";

export interface ControlOverlay {
  ukrainePlacementPolygon: Coordinates[];
  occupiedPolygons: Coordinates[][];
  frontline: Coordinates[];
  waterPlacementPolygons: Coordinates[][];
}

export const CONTROL_OVERLAY_STORAGE_KEY = "shieldline-control-overlay-v1";

// Static, simplified editorial overlay. It is not a live front map.
export const defaultControlOverlay: ControlOverlay = {
  ukrainePlacementPolygon: [
    { lat: 52.35, lng: 22.15 },
    { lat: 52.35, lng: 31.85 },
    { lat: 51.75, lng: 34.45 },
    { lat: 50.45, lng: 36.25 },
    { lat: 49.2, lng: 40.25 },
    { lat: 47.85, lng: 39.35 },
    { lat: 46.25, lng: 38.45 },
    { lat: 45.35, lng: 36.8 },
    { lat: 44.45, lng: 34.65 },
    { lat: 44.35, lng: 33.2 },
    { lat: 44.9, lng: 30.25 },
    { lat: 45.45, lng: 28.15 },
    { lat: 46.45, lng: 27.2 },
    { lat: 48.1, lng: 22.1 },
    { lat: 50.65, lng: 23.0 },
  ],
  occupiedPolygons: [
    [
      { lat: 48.9, lng: 37.0 },
      { lat: 49.2, lng: 39.8 },
      { lat: 47.1, lng: 39.3 },
      { lat: 46.3, lng: 36.4 },
      { lat: 46.2, lng: 33.9 },
      { lat: 47.2, lng: 34.2 },
      { lat: 47.7, lng: 35.1 },
      { lat: 48.25, lng: 36.0 },
    ],
    [
      { lat: 46.4, lng: 32.2 },
      { lat: 46.4, lng: 35.7 },
      { lat: 45.2, lng: 36.4 },
      { lat: 44.4, lng: 33.4 },
      { lat: 45.1, lng: 30.7 },
    ],
  ],
  frontline: [
    { lat: 50.85, lng: 35.1 },
    { lat: 50.25, lng: 36.0 },
    { lat: 49.55, lng: 36.5 },
    { lat: 48.85, lng: 37.2 },
    { lat: 48.15, lng: 37.0 },
    { lat: 47.75, lng: 36.1 },
    { lat: 47.35, lng: 35.2 },
    { lat: 46.95, lng: 34.2 },
    { lat: 46.7, lng: 33.1 },
  ],
  waterPlacementPolygons: [
    [
      { lat: 46.35, lng: 27.2 },
      { lat: 46.45, lng: 30.7 },
      { lat: 45.95, lng: 32.8 },
      { lat: 45.1, lng: 35.4 },
      { lat: 43.2, lng: 36.8 },
      { lat: 42.85, lng: 29.0 },
      { lat: 44.1, lng: 27.0 },
    ],
    [
      { lat: 47.35, lng: 35.45 },
      { lat: 47.65, lng: 39.25 },
      { lat: 46.0, lng: 39.35 },
      { lat: 45.1, lng: 37.0 },
      { lat: 45.3, lng: 35.0 },
    ],
  ],
};

function isFiniteCoordinate(value: unknown): value is Coordinates {
  const candidate = value as Coordinates;
  return Number.isFinite(candidate?.lat) && Number.isFinite(candidate?.lng);
}

function cleanLine(value: unknown, fallback: Coordinates[], minPoints = 2) {
  if (!Array.isArray(value)) return fallback;
  const points = value.filter(isFiniteCoordinate).map((point) => ({ lat: point.lat, lng: point.lng }));
  return points.length >= minPoints ? points : fallback;
}

function cleanPolygons(value: unknown, fallback: Coordinates[][]) {
  if (!Array.isArray(value)) return fallback;
  const polygons = value
    .map((polygon) => cleanLine(polygon, [], 3))
    .filter((polygon) => polygon.length >= 3);
  return polygons;
}

function squaredDistance(left: Coordinates, right: Coordinates) {
  const dLat = left.lat - right.lat;
  const dLng = left.lng - right.lng;
  return dLat * dLat + dLng * dLng;
}

function nearestPointIndex(points: Coordinates[], target: Coordinates) {
  return points.reduce((best, point, index) => (
    squaredDistance(point, target) < squaredDistance(points[best], target) ? index : best
  ), 0);
}

function wrappedSegment(points: Coordinates[], startIndex: number, endIndex: number) {
  if (startIndex <= endIndex) return points.slice(startIndex, endIndex + 1);
  return [...points.slice(startIndex), ...points.slice(0, endIndex + 1)];
}

function averageLng(points: Coordinates[]) {
  return points.reduce((sum, point) => sum + point.lng, 0) / points.length;
}

export function createOccupiedPolygonToPlacementEdge(frontline: Coordinates[], placementPolygon = defaultControlOverlay.ukrainePlacementPolygon) {
  if (frontline.length < 2 || placementPolygon.length < 3) return [];
  const startIndex = nearestPointIndex(placementPolygon, frontline[0]);
  const endIndex = nearestPointIndex(placementPolygon, frontline[frontline.length - 1]);
  const forwardSegment = wrappedSegment(placementPolygon, startIndex, endIndex);
  const reverseSegment = wrappedSegment(placementPolygon, endIndex, startIndex).reverse();
  const frontierLng = averageLng(frontline);
  const borderSegment = averageLng(forwardSegment) >= frontierLng && averageLng(forwardSegment) >= averageLng(reverseSegment)
    ? forwardSegment
    : reverseSegment;
  return [
    ...frontline.map((point) => ({ ...point })),
    ...borderSegment.reverse().map((point) => ({ ...point })),
  ];
}

export function readSavedControlOverlay(): Partial<ControlOverlay> | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(CONTROL_OVERLAY_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<ControlOverlay>;
    return {
      ukrainePlacementPolygon: cleanLine(parsed.ukrainePlacementPolygon, defaultControlOverlay.ukrainePlacementPolygon, 3),
      occupiedPolygons: cleanPolygons(parsed.occupiedPolygons, defaultControlOverlay.occupiedPolygons),
      frontline: cleanLine(parsed.frontline, defaultControlOverlay.frontline),
      waterPlacementPolygons: cleanPolygons(parsed.waterPlacementPolygons, defaultControlOverlay.waterPlacementPolygons),
    };
  } catch {
    return null;
  }
}

export function getControlOverlay(): ControlOverlay {
  const saved = readSavedControlOverlay();
  return {
    ukrainePlacementPolygon: saved?.ukrainePlacementPolygon || defaultControlOverlay.ukrainePlacementPolygon,
    occupiedPolygons: saved?.occupiedPolygons || defaultControlOverlay.occupiedPolygons,
    frontline: saved?.frontline || defaultControlOverlay.frontline,
    waterPlacementPolygons: saved?.waterPlacementPolygons || defaultControlOverlay.waterPlacementPolygons,
  };
}

export function saveControlOverlay(overlay: ControlOverlay) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(CONTROL_OVERLAY_STORAGE_KEY, JSON.stringify(overlay));
}

export function resetControlOverlay() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(CONTROL_OVERLAY_STORAGE_KEY);
}

function apiUrl(basePath: string) {
  const normalized = (basePath || "/shieldline/").replace(/\/+$/, "");
  return `${normalized}/api/control-overlay`;
}

function adminAuthUrl(basePath: string) {
  return `${apiUrl(basePath)}/auth`;
}

export async function hydrateControlOverlayFromServer(basePath: string) {
  try {
    const response = await fetch(apiUrl(basePath), { cache: "no-store" });
    if (!response.ok) return false;
    const payload = await response.json() as { overlay?: Partial<ControlOverlay> | null };
    if (!payload.overlay) return false;
    saveControlOverlay({
      ukrainePlacementPolygon: cleanLine(payload.overlay.ukrainePlacementPolygon, defaultControlOverlay.ukrainePlacementPolygon, 3),
      occupiedPolygons: cleanPolygons(payload.overlay.occupiedPolygons, defaultControlOverlay.occupiedPolygons),
      frontline: cleanLine(payload.overlay.frontline, defaultControlOverlay.frontline),
      waterPlacementPolygons: cleanPolygons(payload.overlay.waterPlacementPolygons, defaultControlOverlay.waterPlacementPolygons),
    });
    return true;
  } catch {
    return false;
  }
}

export async function saveControlOverlayToServer(basePath: string, overlay: ControlOverlay, password: string) {
  const response = await fetch(apiUrl(basePath), {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "X-Shieldline-Admin-Password": password,
    },
    body: JSON.stringify({ overlay }),
  });
  if (!response.ok) {
    if (response.status === 404) throw new Error("Server API is not available.");
    const payload = await response.json().catch(() => ({} as { error?: string }));
    throw new Error(payload.error || "Could not save control overlay.");
  }
}

export async function verifyControlOverlayAdminPassword(basePath: string, password: string) {
  const response = await fetch(adminAuthUrl(basePath), {
    method: "POST",
    headers: {
      "X-Shieldline-Admin-Password": password,
    },
  });
  if (!response.ok) {
    if (response.status === 404) throw new Error("Server API is not available.");
    const payload = await response.json().catch(() => ({} as { error?: string }));
    throw new Error(payload.error || "Invalid admin password.");
  }
  const payload = await response.json().catch(() => ({} as { ok?: boolean }));
  if (!payload.ok) throw new Error("Invalid admin password.");
}
