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
