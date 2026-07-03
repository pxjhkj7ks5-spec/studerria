import { unitDefinitions } from "../data/units";
import type {
  CityId,
  Coordinates,
  DefenseBattery,
  GameState,
  ImpactMarker,
  IntelEntry,
  InterceptorShot,
  LiveThreat,
  ThreatKind,
  UnitDefinition,
  UnitKind,
} from "../types/game";
import { clamp, createId, pick, weightedChance } from "./math";

const SIMULATION_SPEED = 600;
const MAX_LIVE_THREATS = 14;
const UKRAINE_BOUNDS = {
  minLat: 44.4,
  maxLat: 52.4,
  minLng: 22.0,
  maxLng: 40.6,
};

const originSectors: Coordinates[] = [
  { lat: 51.8, lng: 40.0 },
  { lat: 49.7, lng: 41.0 },
  { lat: 46.0, lng: 39.6 },
  { lat: 45.4, lng: 28.0 },
  { lat: 52.0, lng: 25.0 },
];

const threatKinds: ThreatKind[] = ["drone", "missile", "decoy", "combined", "saturation"];

const rangeByTier: Record<DefenseBattery["coverageTier"], number> = {
  I: 0.85,
  II: 1.35,
  III: 1.9,
};

function cloneState(state: GameState): GameState {
  return {
    ...state,
    resources: { ...state.resources },
    cities: state.cities.map((city) => ({ ...city })),
    infrastructure: state.infrastructure.map((node) => ({ ...node })),
    units: state.units.map((unit) => ({ ...unit })),
    batteries: state.batteries.map((battery) => ({ ...battery })),
    liveThreats: state.liveThreats.map((threat) => ({ ...threat })),
    interceptorShots: state.interceptorShots.map((shot) => ({ ...shot })),
    impactMarkers: state.impactMarkers.map((marker) => ({ ...marker })),
    log: state.log.map((entry) => ({ ...entry })),
    forecast: { ...state.forecast },
  };
}

export function formatClock(elapsedMs: number) {
  const simulatedMinutes = Math.floor((elapsedMs / 1000) * 10);
  const hours = Math.floor(simulatedMinutes / 60);
  const minutes = simulatedMinutes % 60;
  return `T+${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
}

function pushLog(entries: IntelEntry[], elapsedMs: number, title: string, body: string, tone: IntelEntry["tone"]) {
  entries.unshift({
    id: `${Math.floor(elapsedMs)}-${entries.length}-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
    time: formatClock(elapsedMs),
    title,
    body,
    tone,
  });
  entries.splice(24);
}

function getUnitDefinition(kind: UnitKind): UnitDefinition {
  const unit = unitDefinitions.find((item) => item.kind === kind);
  if (!unit) throw new Error(`Unknown unit kind: ${kind}`);
  return unit;
}

function nearestCityId(state: GameState, position: Coordinates): CityId {
  return state.cities
    .map((city) => ({
      cityId: city.id,
      score: Math.abs(city.coordinates.lat - position.lat) + Math.abs(city.coordinates.lng - position.lng),
    }))
    .sort((left, right) => left.score - right.score)[0].cityId;
}

export function quantizePlacement(position: Coordinates): Coordinates {
  return {
    lat: clamp(Math.round(position.lat * 4) / 4, UKRAINE_BOUNDS.minLat, UKRAINE_BOUNDS.maxLat),
    lng: clamp(Math.round(position.lng * 4) / 4, UKRAINE_BOUNDS.minLng, UKRAINE_BOUNDS.maxLng),
  };
}

function batteryTier(unit: UnitDefinition): DefenseBattery["coverageTier"] {
  if (unit.rangeLevel >= 3) return "III";
  if (unit.rangeLevel >= 2) return "II";
  return "I";
}

export function placeBattery(state: GameState, kind: UnitKind, position: Coordinates, random: () => number = Math.random): GameState {
  const unit = getUnitDefinition(kind);
  if (state.status !== "active" || state.resources.budget < unit.cost) return state;

  const next = cloneState(state);
  const quantized = quantizePlacement(position);
  const tier = batteryTier(unit);
  next.resources.budget = clamp(next.resources.budget - unit.cost, 0, 999);
  next.batteries.push({
    id: createId("battery", Math.floor(next.elapsedMs), random),
    kind,
    position: quantized,
    coverageTier: tier,
    coverageRadius: rangeByTier[tier],
    readiness: unit.readiness,
    cooldownMs: 0,
    assignedCityId: nearestCityId(next, quantized),
  });
  pushLog(next.log, next.elapsedMs, `${unit.name} Placed`, `${unit.name} is active in Coverage ${tier}.`, "success");
  return next;
}

export function removeBattery(state: GameState, batteryId: string): GameState {
  const next = cloneState(state);
  const battery = next.batteries.find((item) => item.id === batteryId);
  if (!battery) return next;
  const unit = getUnitDefinition(battery.kind);
  next.batteries = next.batteries.filter((item) => item.id !== batteryId);
  next.resources.budget = clamp(next.resources.budget + Math.round(unit.cost * 0.45), 0, 999);
  pushLog(next.log, next.elapsedMs, `${unit.shortName} Recalled`, "A defense unit was recalled and partial budget was recovered.", "info");
  return next;
}

function threatPosition(threat: LiveThreat): Coordinates {
  return {
    lat: threat.origin.lat + (threat.target.lat - threat.origin.lat) * threat.progress,
    lng: threat.origin.lng + (threat.target.lng - threat.origin.lng) * threat.progress,
  };
}

function abstractDistance(left: Coordinates, right: Coordinates) {
  const lat = left.lat - right.lat;
  const lng = left.lng - right.lng;
  return Math.sqrt(lat * lat + lng * lng);
}

function spawnThreat(state: GameState, random: () => number): LiveThreat {
  const node = pick(state.infrastructure, random);
  const kind = pick(threatKinds, random);
  const difficulty: Record<ThreatKind, number> = {
    drone: 26,
    missile: 46,
    decoy: 20,
    combined: 54,
    saturation: 62,
  };
  const speed: Record<ThreatKind, number> = {
    drone: 0.000045,
    missile: 0.000085,
    decoy: 0.000055,
    combined: 0.000065,
    saturation: 0.00005,
  };
  return {
    id: createId("live-threat", Math.floor(state.elapsedMs), random),
    kind,
    status: "inbound",
    origin: pick(originSectors, random),
    target: node.coordinates,
    targetNodeId: node.id,
    targetCityId: node.cityId,
    progress: 0,
    speed: speed[kind] * (0.8 + random() * 0.55),
    difficulty: difficulty[kind] + state.wavePressure * 0.18,
    damage: kind === "decoy" ? 0 : 10 + random() * 18,
    detected: false,
    saturation: kind === "saturation" ? 1.7 : kind === "combined" ? 1.25 : 1,
  };
}

function maybeSpawnThreat(state: GameState, deltaMs: number, random: () => number) {
  if (state.liveThreats.length >= MAX_LIVE_THREATS) return;
  const pressure = 0.00018 + state.wavePressure * 0.000003;
  if (random() < pressure * deltaMs) {
    const threat = spawnThreat(state, random);
    state.liveThreats.push(threat);
    pushLog(state.log, state.elapsedMs, "Track Warning", "Uncertain inbound track appeared on the tactical map.", "warning");
  }
}

function detectThreats(state: GameState, random: () => number) {
  for (const threat of state.liveThreats) {
    if (threat.detected) continue;
    const position = threatPosition(threat);
    const detectionScore = state.batteries.reduce((score, battery) => {
      const unit = getUnitDefinition(battery.kind);
      const distance = abstractDistance(position, battery.position);
      if (distance > battery.coverageRadius * 1.25) return score;
      return score + unit.detectionBonus * (battery.readiness / 100) * (1 - distance / (battery.coverageRadius * 1.35));
    }, 16);
    if (weightedChance(detectionScore - threat.difficulty * 0.25, random)) {
      threat.detected = true;
      threat.status = "detected";
      pushLog(state.log, state.elapsedMs, "Target Detected", `${threat.kind} track classified with low-confidence intelligence.`, "info");
    }
  }
}

function updateShots(state: GameState, deltaMs: number) {
  const resolvedThreatIds = new Set<string>();
  const nextShots: InterceptorShot[] = [];
  for (const shot of state.interceptorShots) {
    const nextProgress = shot.progress + shot.speed * deltaMs;
    if (nextProgress >= 1) {
      const threat = state.liveThreats.find((item) => item.id === shot.threatId);
      if (threat) {
        threat.status = "intercepted";
        resolvedThreatIds.add(threat.id);
        state.interceptions += 1;
        state.impactMarkers.push({
          id: createId("intercept", Math.floor(state.elapsedMs), Math.random),
          position: threatPosition(threat),
          tone: "intercept",
          ttlMs: 1800,
        });
        pushLog(state.log, state.elapsedMs, "Intercept Confirmed", "A defense unit neutralized a tracked target inside abstract coverage.", "success");
      }
    } else {
      nextShots.push({ ...shot, progress: nextProgress });
    }
  }
  state.interceptorShots = nextShots;
  if (resolvedThreatIds.size) {
    state.liveThreats = state.liveThreats.filter((threat) => !resolvedThreatIds.has(threat.id));
  }
}

function engageThreats(state: GameState, random: () => number) {
  for (const battery of state.batteries) {
    const unit = getUnitDefinition(battery.kind);
    if (unit.interceptionPower <= 0 || battery.cooldownMs > 0 || state.resources.ammo < unit.ammoUse) continue;
    const candidate = state.liveThreats
      .filter((threat) => threat.detected && threat.status !== "engaged")
      .map((threat) => ({ threat, distance: abstractDistance(threatPosition(threat), battery.position) }))
      .filter((entry) => entry.distance <= battery.coverageRadius)
      .sort((left, right) => right.threat.progress - left.threat.progress)[0];
    if (!candidate) continue;

    const chance = unit.interceptionPower * (battery.readiness / 100)
      - candidate.threat.difficulty * 0.24
      - candidate.threat.saturation * 4
      + (1 - candidate.distance / battery.coverageRadius) * 18;
    if (!weightedChance(chance, random)) {
      battery.cooldownMs = 1100;
      battery.readiness = clamp(battery.readiness - 2, 35, 100);
      continue;
    }

    candidate.threat.status = "engaged";
    state.resources.ammo = clamp(state.resources.ammo - unit.ammoUse, 0, 999);
    battery.cooldownMs = 2600 + unit.ammoUse * 180;
    battery.readiness = clamp(battery.readiness - 3.5, 35, 100);
    state.interceptorShots.push({
      id: createId("shot", Math.floor(state.elapsedMs), random),
      batteryId: battery.id,
      threatId: candidate.threat.id,
      from: battery.position,
      to: threatPosition(candidate.threat),
      progress: 0,
      speed: 0.0017,
    });
    pushLog(state.log, state.elapsedMs, "Engagement", `${unit.shortName} fired inside Coverage ${battery.coverageTier}.`, "info");
  }
}

function applyImpact(state: GameState, threat: LiveThreat) {
  const node = state.infrastructure.find((item) => item.id === threat.targetNodeId);
  const city = state.cities.find((item) => item.id === threat.targetCityId);
  if (!node || !city) return;

  const damage = threat.kind === "decoy" ? 2 : threat.damage;
  node.integrity = clamp(node.integrity - damage);
  city.damage = clamp(city.damage + damage * 0.35);
  city.infrastructure = clamp(city.infrastructure - damage * 0.25);
  city.energy = clamp(city.energy - (node.kind === "energy" ? damage * 0.42 : damage * 0.12));
  state.resources.energy = clamp(state.resources.energy - (node.kind === "energy" ? damage * 0.22 : damage * 0.06));
  state.resources.morale = clamp(state.resources.morale - (node.critical ? 2.5 : 1.4));
  state.impacts += 1;
  state.impactMarkers.push({ id: createId("impact", Math.floor(state.elapsedMs), Math.random), position: node.coordinates, tone: "impact", ttlMs: 2600 });
  pushLog(state.log, state.elapsedMs, "Impact", `${node.name} was disrupted by an unresolved ${threat.kind} track.`, "danger");
}

function updateThreats(state: GameState, deltaMs: number) {
  const remaining: LiveThreat[] = [];
  for (const threat of state.liveThreats) {
    const next = { ...threat, progress: threat.progress + threat.speed * deltaMs * (SIMULATION_SPEED / 600) };
    if (next.progress >= 1) {
      applyImpact(state, next);
    } else {
      remaining.push(next);
    }
  }
  state.liveThreats = remaining;
}

function updateResourcesAndTimers(state: GameState, deltaMs: number) {
  for (const battery of state.batteries) {
    battery.cooldownMs = Math.max(0, battery.cooldownMs - deltaMs);
    battery.readiness = clamp(battery.readiness + deltaMs * 0.00022, 35, 100);
  }
  state.impactMarkers = state.impactMarkers
    .map((marker) => ({ ...marker, ttlMs: marker.ttlMs - deltaMs }))
    .filter((marker) => marker.ttlMs > 0);
  state.wavePressure = clamp(state.wavePressure + deltaMs * 0.00022, 10, 100);
  state.resources.budget = clamp(state.resources.budget + deltaMs * 0.00042, 0, 999);
  state.resources.ammo = clamp(state.resources.ammo + deltaMs * 0.00022, 0, 999);
}

function evaluateLiveStatus(state: GameState) {
  const destroyedCritical = state.infrastructure.filter((node) => node.critical && node.integrity <= 0).length;
  if (state.resources.morale <= 0) {
    state.status = "lost";
    state.statusReason = "National morale collapsed.";
  } else if (state.resources.energy <= 0) {
    state.status = "lost";
    state.statusReason = "Energy stability collapsed.";
  } else if (destroyedCritical >= 3) {
    state.status = "lost";
    state.statusReason = "Too many critical infrastructure nodes were destroyed.";
  }
}

export function tickSimulation(current: GameState, deltaMs: number, random: () => number = Math.random): GameState {
  if (current.status !== "active") return current;
  const state = cloneState(current);
  const safeDelta = clamp(deltaMs, 0, 1000);
  state.elapsedMs += safeDelta;
  updateResourcesAndTimers(state, safeDelta);
  maybeSpawnThreat(state, safeDelta, random);
  detectThreats(state, random);
  engageThreats(state, random);
  updateShots(state, safeDelta);
  updateThreats(state, safeDelta);
  evaluateLiveStatus(state);
  return state;
}
