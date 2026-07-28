import type { ThreatKind } from "../types/game";

export interface SharedThreatFlightProfile {
  speedKph: number;
  altitudeM: readonly [number, number];
  timeCompression: number;
  representativeDistanceKm: number;
  maximumTrackedDurationMs?: number;
}

export const THREAT_FLIGHT_PROFILES: Readonly<Record<ThreatKind, SharedThreatFlightProfile>>;

export function routeDistanceKm(points: ReadonlyArray<{ lat: number; lng: number }>): number;
export function trimRouteToTrackedDistance(kind: ThreatKind, points: ReadonlyArray<{ lat: number; lng: number }>, maximumDurationMs?: number): Array<{ lat: number; lng: number }>;
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
