import type { ThreatKind } from "../types/game";

export interface SharedThreatFlightProfile {
  speedKph: number;
  altitudeM: readonly [number, number];
  timeCompression: number;
  representativeDistanceKm: number;
}

export const THREAT_FLIGHT_PROFILES: Readonly<Record<ThreatKind, SharedThreatFlightProfile>>;
export const GAMEPLAY_FLIGHT_SPEED_SCALE: number;
export const MISSILE_FLIGHT_SPEED_SCALE: number;

export function routeDistanceKm(points: ReadonlyArray<{ lat: number; lng: number }>): number;
export function flightDurationForDistance(kind: ThreatKind, speedKph: number, distanceKm: number): number;
export function flightDurationForSpeed(kind: ThreatKind, speedKph: number): number;

export function sampledThreatTelemetry(
  kind: ThreatKind,
  random: () => number,
  distanceKm?: number,
): {
  speedKph: number;
  altitudeM: number;
  flightDurationMs: number;
};
