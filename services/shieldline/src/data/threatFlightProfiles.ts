import type { ThreatKind } from "../types/game";
import { THREAT_FLIGHT_PROFILES } from "../game/threatFlightModel.mjs";

interface ThreatFlightProfile {
  label: string;
  speedKph: readonly [number, number];
  altitudeM: readonly [number, number];
}

export interface ThreatTelemetry {
  speedKph: number;
  altitudeM: number;
}

const labels: Record<ThreatKind, string> = {
  drone: "UAV",
  ballistic: "OTRK",
  cruise: "Cruise",
  decoy: "Decoy",
  combined: "Combined",
  saturation: "UAV swarm",
  geran2: "Geran-2",
  gerbera: "Gerbera",
  parodiya: "Parodiya",
  kh101: "X-101",
  kalibr: "Kalibr",
  iskander: "Iskander-M",
  recon: "Recon",
  "low-signature-cruise": "Low-signature cruise",
  jammer: "Jammer escort",
};

export const threatFlightProfiles = Object.fromEntries(
  Object.entries(THREAT_FLIGHT_PROFILES).map(([kind, profile]) => [kind, {
    label: labels[kind as ThreatKind],
    speedKph: profile.speedKph,
    altitudeM: profile.altitudeM,
  }]),
) as Record<ThreatKind, ThreatFlightProfile>;

function hashFraction(value: string) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash = Math.imul(hash ^ value.charCodeAt(index), 16777619);
  }
  return (hash >>> 0) / 4294967295;
}

function rangedValue(range: readonly [number, number], seed: string, step: number) {
  const value = range[0] + hashFraction(seed) * (range[1] - range[0]);
  return Math.round(value / step) * step;
}

export function threatTelemetryFor(kind: ThreatKind, seed: string): ThreatTelemetry {
  const profile = threatFlightProfiles[kind];
  return {
    speedKph: rangedValue(profile.speedKph, `${seed}:speed`, 10),
    altitudeM: rangedValue(profile.altitudeM, `${seed}:altitude`, profile.altitudeM[1] >= 10_000 ? 100 : 10),
  };
}

export function threatDisplayName(kind: ThreatKind) {
  return threatFlightProfiles[kind].label;
}

export function formatThreatAltitude(altitudeM: number) {
  if (altitudeM < 1_000) return `${Math.round(altitudeM / 10) * 10} м`;
  const kilometers = Math.round((altitudeM / 1_000) * 10) / 10;
  return `${Number.isInteger(kilometers) ? kilometers.toFixed(0) : kilometers.toFixed(1)} км`;
}

export function formatThreatSpeed(speedKph: number) {
  return `${Math.round(speedKph / 10) * 10} км/год`;
}
