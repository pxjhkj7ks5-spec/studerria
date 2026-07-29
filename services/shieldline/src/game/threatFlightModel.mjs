export const THREAT_FLIGHT_PROFILES = Object.freeze({
  drone: { speedKph: 160, altitudeM: [70, 320], timeCompression: 55, representativeDistanceKm: 320 },
  ballistic: { speedKph: 4_800, altitudeM: [18_000, 50_000], timeCompression: 3, representativeDistanceKm: 200 },
  cruise: { speedKph: 800, altitudeM: [30, 180], timeCompression: 20, representativeDistanceKm: 600 },
  decoy: { speedKph: 140, altitudeM: [90, 420], timeCompression: 65, representativeDistanceKm: 300 },
  combined: { speedKph: 820, altitudeM: [40, 220], timeCompression: 20, representativeDistanceKm: 600 },
  saturation: { speedKph: 170, altitudeM: [60, 260], timeCompression: 50, representativeDistanceKm: 300 },
  geran2: { speedKph: 170, altitudeM: [60, 180], timeCompression: 50, representativeDistanceKm: 300 },
  gerbera: { speedKph: 150, altitudeM: [80, 300], timeCompression: 55, representativeDistanceKm: 280 },
  parodiya: { speedKph: 130, altitudeM: [100, 360], timeCompression: 65, representativeDistanceKm: 280 },
  kh101: { speedKph: 780, altitudeM: [30, 120], timeCompression: 18, representativeDistanceKm: 500 },
  kalibr: { speedKph: 850, altitudeM: [20, 100], timeCompression: 12, representativeDistanceKm: 400 },
  iskander: { speedKph: 5_200, altitudeM: [20_000, 50_000], timeCompression: 3, representativeDistanceKm: 200 },
  recon: { speedKph: 200, altitudeM: [500, 1_800], timeCompression: 44, representativeDistanceKm: 300 },
  "low-signature-cruise": { speedKph: 760, altitudeM: [25, 100], timeCompression: 28, representativeDistanceKm: 800 },
  jammer: { speedKph: 520, altitudeM: [1_500, 5_000], timeCompression: 25, representativeDistanceKm: 500 },
});

export const GAMEPLAY_FLIGHT_SPEED_SCALE = 1.1;
export const MISSILE_FLIGHT_SPEED_SCALE = 1.06;

const MISSILE_THREAT_KINDS = new Set([
  "ballistic",
  "combined",
  "cruise",
  "iskander",
  "kalibr",
  "kh101",
  "low-signature-cruise",
]);

function segmentDistanceKm(left, right) {
  const latitudeKm = (right.lat - left.lat) * 111;
  const middleLatitude = (left.lat + right.lat) * Math.PI / 360;
  const longitudeKm = (right.lng - left.lng) * 111 * Math.max(.35, Math.cos(middleLatitude));
  return Math.hypot(latitudeKm, longitudeKm);
}

export function routeDistanceKm(points) {
  if (!Array.isArray(points) || points.length < 2) return 0;
  return points.slice(1).reduce((sum, point, index) => sum + segmentDistanceKm(points[index], point), 0);
}

export function flightDurationForDistance(kind, speedKph, distanceKm) {
  const profile = THREAT_FLIGHT_PROFILES[kind] || THREAT_FLIGHT_PROFILES.drone;
  const safeSpeed = Math.max(1, Number(speedKph) || profile.speedKph);
  const safeDistance = Math.max(1, Number(distanceKm) || profile.representativeDistanceKm);
  const missileScale = MISSILE_THREAT_KINDS.has(kind) ? MISSILE_FLIGHT_SPEED_SCALE : 1;
  return Math.max(5_000, Math.round((safeDistance / safeSpeed) * 3_600_000 / (profile.timeCompression * GAMEPLAY_FLIGHT_SPEED_SCALE * missileScale)));
}

export function flightDurationForSpeed(kind, speedKph) {
  const profile = THREAT_FLIGHT_PROFILES[kind] || THREAT_FLIGHT_PROFILES.drone;
  return flightDurationForDistance(kind, speedKph, profile.representativeDistanceKm);
}

export function sampledThreatTelemetry(kind, random, distanceKm) {
  const profile = THREAT_FLIGHT_PROFILES[kind] || THREAT_FLIGHT_PROFILES.drone;
  const speedKph = profile.speedKph;
  const altitudeStep = profile.altitudeM[1] >= 10_000 ? 100 : 10;
  const altitudeM = Math.round((profile.altitudeM[0] + random() * (profile.altitudeM[1] - profile.altitudeM[0])) / altitudeStep) * altitudeStep;
  return {
    speedKph,
    altitudeM,
    flightDurationMs: flightDurationForDistance(kind, speedKph, distanceKm || profile.representativeDistanceKm),
  };
}
