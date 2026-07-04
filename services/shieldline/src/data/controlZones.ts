import type { Coordinates } from "../types/game";

export interface ControlOverlay {
  controlledUkrainePolygon: Coordinates[];
  temporarilyOccupiedPolygons: Coordinates[][];
  frontline: Coordinates[];
  hostileBorder: Coordinates[];
}

// Static, simplified game overlay. It is not a live front map and should be
// replaced by a manually imported official snapshot when available.
export const controlOverlay: ControlOverlay = {
  controlledUkrainePolygon: [
    { lat: 52.25, lng: 23.6 },
    { lat: 52.05, lng: 30.8 },
    { lat: 51.45, lng: 33.6 },
    { lat: 50.7, lng: 34.7 },
    { lat: 49.95, lng: 35.55 },
    { lat: 49.25, lng: 36.35 },
    { lat: 48.65, lng: 35.85 },
    { lat: 48.2, lng: 35.25 },
    { lat: 47.75, lng: 34.65 },
    { lat: 47.45, lng: 33.3 },
    { lat: 47.05, lng: 32.25 },
    { lat: 46.6, lng: 31.05 },
    { lat: 45.35, lng: 29.55 },
    { lat: 45.55, lng: 28.2 },
    { lat: 48.0, lng: 22.15 },
    { lat: 50.45, lng: 23.55 },
  ],
  temporarilyOccupiedPolygons: [
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
  hostileBorder: [
    { lat: 52.2, lng: 31.8 },
    { lat: 51.8, lng: 33.8 },
    { lat: 50.9, lng: 34.7 },
    { lat: 50.1, lng: 35.7 },
    { lat: 49.4, lng: 36.5 },
    { lat: 48.8, lng: 38.1 },
    { lat: 47.9, lng: 39.1 },
    { lat: 46.7, lng: 38.5 },
    { lat: 45.8, lng: 36.8 },
    { lat: 44.7, lng: 33.8 },
  ],
};
