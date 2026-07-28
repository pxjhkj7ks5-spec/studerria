import type { ThreatKind } from "../types/game";

export interface SharedThreatFlightProfile {
  speedKph: readonly [number, number];
  altitudeM: readonly [number, number];
  durationMs: readonly [number, number];
}

export const THREAT_FLIGHT_PROFILES: Readonly<Record<ThreatKind, SharedThreatFlightProfile>>;

export function flightDurationForSpeed(kind: ThreatKind, speedKph: number): number;

export function sampledThreatTelemetry(
  kind: ThreatKind,
  random: () => number,
): {
  speedKph: number;
  altitudeM: number;
  flightDurationMs: number;
};
