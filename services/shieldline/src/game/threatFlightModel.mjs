export const THREAT_FLIGHT_PROFILES = Object.freeze({
  drone: { speedKph: [130, 220], altitudeM: [70, 320], durationMs: [120_000, 180_000] },
  ballistic: { speedKph: [3_200, 6_500], altitudeM: [18_000, 50_000], durationMs: [35_000, 50_000] },
  cruise: { speedKph: [650, 920], altitudeM: [30, 180], durationMs: [120_000, 145_000] },
  decoy: { speedKph: [110, 190], altitudeM: [90, 420], durationMs: [120_000, 180_000] },
  combined: { speedKph: [680, 900], altitudeM: [40, 220], durationMs: [120_000, 145_000] },
  saturation: { speedKph: [140, 210], altitudeM: [60, 260], durationMs: [130_000, 190_000] },
  geran2: { speedKph: [150, 190], altitudeM: [60, 180], durationMs: [120_000, 180_000] },
  gerbera: { speedKph: [130, 180], altitudeM: [80, 300], durationMs: [120_000, 180_000] },
  parodiya: { speedKph: [110, 165], altitudeM: [100, 360], durationMs: [120_000, 180_000] },
  kh101: { speedKph: [700, 850], altitudeM: [30, 120], durationMs: [120_000, 145_000] },
  kalibr: { speedKph: [750, 950], altitudeM: [20, 100], durationMs: [120_000, 145_000] },
  iskander: { speedKph: [3_500, 7_200], altitudeM: [20_000, 50_000], durationMs: [35_000, 50_000] },
  recon: { speedKph: [160, 260], altitudeM: [500, 1_800], durationMs: [110_000, 160_000] },
  "low-signature-cruise": { speedKph: [680, 880], altitudeM: [25, 100], durationMs: [130_000, 160_000] },
  jammer: { speedKph: [420, 720], altitudeM: [1_500, 5_000], durationMs: [90_000, 140_000] },
});

function clamp(value, minimum, maximum) {
  return Math.max(minimum, Math.min(maximum, value));
}

export function flightDurationForSpeed(kind, speedKph) {
  const profile = THREAT_FLIGHT_PROFILES[kind] || THREAT_FLIGHT_PROFILES.drone;
  const [minimumSpeed, maximumSpeed] = profile.speedKph;
  const [minimumDuration, maximumDuration] = profile.durationMs;
  const speedRatio = clamp((Number(speedKph) - minimumSpeed) / Math.max(1, maximumSpeed - minimumSpeed), 0, 1);
  return Math.round(maximumDuration - speedRatio * (maximumDuration - minimumDuration));
}

export function sampledThreatTelemetry(kind, random) {
  const profile = THREAT_FLIGHT_PROFILES[kind] || THREAT_FLIGHT_PROFILES.drone;
  const speedKph = Math.round((profile.speedKph[0] + random() * (profile.speedKph[1] - profile.speedKph[0])) / 10) * 10;
  const altitudeStep = profile.altitudeM[1] >= 10_000 ? 100 : 10;
  const altitudeM = Math.round((profile.altitudeM[0] + random() * (profile.altitudeM[1] - profile.altitudeM[0])) / altitudeStep) * altitudeStep;
  return { speedKph, altitudeM, flightDurationMs: flightDurationForSpeed(kind, speedKph) };
}
