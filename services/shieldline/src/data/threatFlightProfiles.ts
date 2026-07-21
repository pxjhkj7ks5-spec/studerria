import type { ThreatKind } from "../types/game";

interface ThreatFlightProfile {
  label: string;
  speedKph: readonly [number, number];
  altitudeM: readonly [number, number];
}

export interface ThreatTelemetry {
  speedKph: number;
  altitudeM: number;
}

export const threatFlightProfiles: Record<ThreatKind, ThreatFlightProfile> = {
  drone: { label: "UAV", speedKph: [130, 220], altitudeM: [70, 320] },
  ballistic: { label: "OTRK", speedKph: [3_200, 6_500], altitudeM: [18_000, 50_000] },
  cruise: { label: "Cruise", speedKph: [650, 920], altitudeM: [30, 180] },
  decoy: { label: "Decoy", speedKph: [110, 190], altitudeM: [90, 420] },
  combined: { label: "Combined", speedKph: [680, 900], altitudeM: [40, 220] },
  saturation: { label: "UAV swarm", speedKph: [140, 210], altitudeM: [60, 260] },
  geran2: { label: "Geran-2", speedKph: [150, 190], altitudeM: [60, 180] },
  gerbera: { label: "Gerbera", speedKph: [130, 180], altitudeM: [80, 300] },
  parodiya: { label: "Parodiya", speedKph: [110, 165], altitudeM: [100, 360] },
  kh101: { label: "X-101", speedKph: [700, 850], altitudeM: [30, 120] },
  kalibr: { label: "Kalibr", speedKph: [750, 950], altitudeM: [20, 100] },
  iskander: { label: "Iskander-M", speedKph: [3_500, 7_200], altitudeM: [20_000, 50_000] },
  recon: { label: "Recon", speedKph: [160, 260], altitudeM: [500, 1_800] },
  "low-signature-cruise": { label: "Low-signature cruise", speedKph: [680, 880], altitudeM: [25, 100] },
  jammer: { label: "Jammer escort", speedKph: [420, 720], altitudeM: [1_500, 5_000] },
};

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
