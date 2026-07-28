export const THREAT_FLIGHT_PROFILES = Object.freeze({
  drone: { speedKph: 160, altitudeM: [70, 320], timeCompression: 55, representativeDistanceKm: 320 },
  ballistic: { speedKph: 4_800, altitudeM: [18_000, 50_000], timeCompression: 3, representativeDistanceKm: 200, maximumTrackedDurationMs: 50_000 },
  cruise: { speedKph: 800, altitudeM: [30, 180], timeCompression: 20, representativeDistanceKm: 600 },
  decoy: { speedKph: 140, altitudeM: [90, 420], timeCompression: 65, representativeDistanceKm: 300 },
  combined: { speedKph: 820, altitudeM: [40, 220], timeCompression: 20, representativeDistanceKm: 600 },
  saturation: { speedKph: 170, altitudeM: [60, 260], timeCompression: 50, representativeDistanceKm: 300 },
  geran2: { speedKph: 170, altitudeM: [60, 180], timeCompression: 50, representativeDistanceKm: 300 },
  gerbera: { speedKph: 150, altitudeM: [80, 300], timeCompression: 55, representativeDistanceKm: 280 },
  parodiya: { speedKph: 130, altitudeM: [100, 360], timeCompression: 65, representativeDistanceKm: 280 },
  kh101: { speedKph: 780, altitudeM: [30, 120], timeCompression: 18, representativeDistanceKm: 500 },
  kalibr: { speedKph: 850, altitudeM: [20, 100], timeCompression: 12, representativeDistanceKm: 400 },
  iskander: { speedKph: 5_200, altitudeM: [20_000, 50_000], timeCompression: 3, representativeDistanceKm: 200, maximumTrackedDurationMs: 50_000 },
  recon: { speedKph: 200, altitudeM: [500, 1_800], timeCompression: 44, representativeDistanceKm: 300 },
  "low-signature-cruise": { speedKph: 760, altitudeM: [25, 100], timeCompression: 28, representativeDistanceKm: 800 },
  jammer: { speedKph: 520, altitudeM: [1_500, 5_000], timeCompression: 25, representativeDistanceKm: 500 },
});

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

export function trimRouteToTrackedDistance(kind, points, maximumDurationMs) {
  if (!Array.isArray(points) || points.length < 2) return points || [];
  const profile = THREAT_FLIGHT_PROFILES[kind] || THREAT_FLIGHT_PROFILES.drone;
  const trackedDurationMs = Number.isFinite(maximumDurationMs) ? maximumDurationMs : profile.maximumTrackedDurationMs || 150_000;
  const maximumDistanceKm = profile.speedKph * profile.timeCompression * trackedDurationMs / 3_600_000 * .997;
  if (routeDistanceKm(points) <= maximumDistanceKm) return points.map((point) => ({ ...point }));
  const suffix = [{ ...points.at(-1) }];
  let remainingKm = maximumDistanceKm;
  for (let index = points.length - 1; index > 0 && remainingKm > 0; index -= 1) {
    const start = points[index - 1];
    const end = points[index];
    const lengthKm = segmentDistanceKm(start, end);
    if (lengthKm <= remainingKm) {
      suffix.unshift({ ...start });
      remainingKm -= lengthKm;
      continue;
    }
    const ratio = Math.max(0, Math.min(1, 1 - remainingKm / Math.max(.000001, lengthKm)));
    suffix.unshift({
      lat: start.lat + (end.lat - start.lat) * ratio,
      lng: start.lng + (end.lng - start.lng) * ratio,
    });
    remainingKm = 0;
  }
  return suffix;
}

export function flightDurationForDistance(kind, speedKph, distanceKm) {
  const profile = THREAT_FLIGHT_PROFILES[kind] || THREAT_FLIGHT_PROFILES.drone;
  const safeSpeed = Math.max(1, Number(speedKph) || profile.speedKph);
  const safeDistance = Math.max(1, Number(distanceKm) || profile.representativeDistanceKm);
  return Math.max(5_000, Math.round((safeDistance / safeSpeed) * 3_600_000 / profile.timeCompression));
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
