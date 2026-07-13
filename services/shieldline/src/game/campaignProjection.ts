import type { MissionRun, SimulationEvent } from "../domain/contracts";
import type { ImpactMarker, InterceptorShot, LaunchAreaState, LaunchSector, LiveThreat, ThreatKind } from "../types/game";
import { launchSectors as launchSectorCatalogue, threatProfilesForKind } from "./launchSystem.mjs";

export interface CampaignMapProjection {
  elapsedMs: number;
  liveThreats: LiveThreat[];
  interceptorShots: InterceptorShot[];
  impactMarkers: ImpactMarker[];
  launchSectors: LaunchSector[];
  visibleEvents: SimulationEvent[];
  interceptions: number;
  impacts: number;
}

const sectorCity = { north: "chernihiv", south: "odesa", east: "kharkiv", west: "lviv", hq: "kyiv" } as const;

function numberPayload(event: SimulationEvent | undefined, key: string, fallback = 0) {
  const value = Number(event?.payload[key]);
  return Number.isFinite(value) ? value : fallback;
}

function threatKind(event: SimulationEvent | undefined): ThreatKind {
  const value = String(event?.payload.threatKind || "drone") as ThreatKind;
  return ["drone", "ballistic", "cruise", "decoy", "combined", "saturation", "geran2", "gerbera", "parodiya", "kh101", "kalibr", "iskander"].includes(value) ? value : "drone";
}

function heading(from: { lat: number; lng: number }, to: { lat: number; lng: number }) {
  const radians = Math.atan2(to.lng - from.lng, to.lat - from.lat);
  return (radians * 180 / Math.PI + 360) % 360;
}

function waveEvents(run: MissionRun) {
  const ids = new Set(run.events.map((event) => event.waveId).filter((id): id is string => Boolean(id)));
  return [...ids].map((waveId) => ({ waveId, events: run.events.filter((event) => event.waveId === waveId) }));
}

export function projectCampaignRun(run: MissionRun | null, elapsedMs: number): CampaignMapProjection | null {
  if (!run) return null;
  const visibleEvents = run.events.filter((event) => event.occurredAtMs <= elapsedMs);
  const liveThreats: LiveThreat[] = [];
  const interceptorShots: InterceptorShot[] = [];
  const impactMarkers: ImpactMarker[] = [];
  const projectedLaunchSectors = new Map<string, LaunchSector>();

  for (const wave of waveEvents(run)) {
    const warning = wave.events.find((event) => event.type === "launch.warning");
    const launched = wave.events.find((event) => event.type === "threat.launched");
    const detected = wave.events.find((event) => event.type === "track.detected" || event.type === "wave.detected");
    const fired = wave.events.find((event) => event.type === "battery.fired");
    const intercepted = wave.events.find((event) => event.type === "interception");
    const impact = wave.events.find((event) => event.type === "impact");
    if (!warning || !launched) continue;

    const origin = { lat: numberPayload(launched, "originLat"), lng: numberPayload(launched, "originLng") };
    const target = { lat: numberPayload(launched, "targetLat"), lng: numberPayload(launched, "targetLng") };
    const kind = threatKind(launched);
    const launchSectorId = String(launched.payload.launchSectorId || warning.sectorId || "unknown-sector");
    const launchSector = launchSectorCatalogue.find((sector) => sector.id === launchSectorId) || {
      id: launchSectorId,
      name: String(launched.payload.launchSectorName || warning.sectorId || "Archived launch corridor"),
      lat: numberPayload(launched, "launchSectorLat", origin.lat),
      lng: numberPayload(launched, "launchSectorLng", origin.lng),
      radiusKm: numberPayload(launched, "launchSectorRadiusKm", 80),
      weight: 1,
      threats: threatProfilesForKind(kind),
      role: "Archived broad launch corridor",
    };
    const travelDurationMs = numberPayload(launched, "flightDurationMs", 120_000);
    // Missed tracks continue after a partial interception; a fully intercepted
    // wave disappears at the actual intercept point instead of racing to its target.
    const flightEnd = impact?.occurredAtMs ?? intercepted?.occurredAtMs ?? launched.occurredAtMs + travelDurationMs;
    const progress = Math.max(0, Math.min(1, (elapsedMs - launched.occurredAtMs) / Math.max(1, travelDurationMs)));

    if (elapsedMs >= warning.occurredAtMs) {
      const state = elapsedMs < launched.occurredAtMs ? "warning" : elapsedMs < (detected?.occurredAtMs ?? flightEnd) ? "launching" : "cooldown";
      const activeThreats = threatProfilesForKind(kind).filter((profile) => launchSector.threats.includes(profile));
      const projectedSector: LaunchSector = {
        ...launchSector,
        id: `campaign-launch-${wave.waveId}`,
        name: "Точка пуску",
        lat: origin.lat,
        lng: origin.lng,
        radiusKm: 1,
        role: `${launchSector.name} · ${kind}`,
        threats: activeThreats.length ? activeThreats : [...launchSector.threats],
        state,
        targetCoordinates: target,
        targetHeadingDeg: heading(origin, target),
      };
      const current = projectedLaunchSectors.get(projectedSector.id);
      const priority: Record<LaunchAreaState, number> = { idle: 0, cooldown: 1, warning: 2, launching: 3 };
      if (!current || priority[projectedSector.state || "idle"] >= priority[current.state || "idle"]) {
        projectedLaunchSectors.set(projectedSector.id, projectedSector);
      }
    }

    if (elapsedMs >= launched.occurredAtMs && elapsedMs < flightEnd) {
      const targetSector = String(launched.targetId || detected?.sectorId || "hq") as keyof typeof sectorCity;
      liveThreats.push({
        id: `${wave.waveId}-track`,
        kind,
        status: fired && intercepted && elapsedMs >= fired.occurredAtMs && elapsedMs < intercepted.occurredAtMs ? "engaged" : "inbound",
        origin,
        target,
        targetCityId: sectorCity[targetSector] || "kyiv",
        launchSectorId: launchSector.id,
        launchSectorName: launchSector.name,
        progress,
        speed: 1 / Math.max(1, travelDurationMs),
        difficulty: numberPayload(detected, "difficulty", 50),
        damage: numberPayload(launched, "tracks", 1) * 4,
        confidence: detected && elapsedMs >= detected.occurredAtMs ? 97 : 42,
        saturation: numberPayload(launched, "tracks", 1),
        headingDeg: heading(origin, target),
        revealed: Boolean(detected && elapsedMs >= detected.occurredAtMs),
        trackQuality: detected && elapsedMs >= detected.occurredAtMs ? 96 : 30,
        reward: 0,
      });
    }

    if (fired && intercepted && elapsedMs >= fired.occurredAtMs && elapsedMs < intercepted.occurredAtMs) {
      const to = {
        lat: numberPayload(intercepted, "latitude", (origin.lat + target.lat) / 2),
        lng: numberPayload(intercepted, "longitude", (origin.lng + target.lng) / 2),
      };
      interceptorShots.push({
        id: `${wave.waveId}-shot`,
        batteryId: String(fired.assetId || "sector-defense"),
        threatId: `${wave.waveId}-track`,
        from: target,
        to,
        progress: Math.max(0, Math.min(1, (elapsedMs - fired.occurredAtMs) / Math.max(1, intercepted.occurredAtMs - fired.occurredAtMs))),
        speed: 1 / Math.max(1, intercepted.occurredAtMs - fired.occurredAtMs),
        style: "missile",
      });
    }

    for (const outcome of [intercepted, impact]) {
      if (!outcome || elapsedMs < outcome.occurredAtMs || elapsedMs - outcome.occurredAtMs > 9_000) continue;
      impactMarkers.push({
        id: outcome.id,
        position: {
          lat: numberPayload(outcome, "latitude", target.lat),
          lng: numberPayload(outcome, "longitude", target.lng),
        },
        tone: outcome.type === "interception" ? "intercept" : "impact",
        ttlMs: Math.max(0, 9_000 - (elapsedMs - outcome.occurredAtMs)),
      });
    }
  }

  return {
    elapsedMs,
    liveThreats,
    interceptorShots,
    impactMarkers,
    launchSectors: [...projectedLaunchSectors.values()],
    visibleEvents,
    interceptions: visibleEvents.filter((event) => event.type === "interception").reduce((sum, event) => sum + numberPayload(event, "count"), 0),
    impacts: visibleEvents.filter((event) => event.type === "impact").reduce((sum, event) => sum + numberPayload(event, "count"), 0),
  };
}
