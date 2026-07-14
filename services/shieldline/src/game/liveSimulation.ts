import { getScenario } from "../data/scenarios";
import { getUnitDefinition } from "../data/units";
import { threatTelemetryFor } from "../data/threatFlightProfiles";
import { createCycleSnapshot, generateAfterActionReport } from "./afterActionReport";
import { buildLogisticsState } from "./logistics";
import { createGuidedCampaignSchedule, guidedStageForElapsed, guidedStageLaunchCount, guidedThreatKind, nextGuidedLaunchDelayMs, sectorIdsForDirection } from "./campaignPacing.mjs";
import { SHOW_LAUNCH_DEBUG, launchSectorCenter, pickWeightedSector, randomPointInSector, sectorSupportsThreat } from "./launchSystem.mjs";
import { clamp, createId, pick, weightedChance } from "./math";
import { applyPlanningActionCosts, applyPlanningRecoveryEffects, closePlanningDay } from "./planningActions";
import { distanceKm, validateBatteryPlacement } from "./placementRules";
import { chooseAttackPlan, createThreatDirectorContext, pickThreatKindForPlan } from "./threatDirector";
import { applyEngagementFatigue, applyRedeployFatigue, enterMaintenance, recoverReadiness } from "./unitReadiness";
import type {
  CityId,
  Coordinates,
  DefenseBattery,
  GameState,
  ImpactMarker,
  IntelEntry,
  InterceptorShot,
  LaunchSector,
  LiveThreat,
  PendingLaunch,
  ThreatKind,
  UnitKind,
} from "../types/game";

const MAX_LIVE_THREATS = 18;
const PLANNING_WINDOW_MS = 30000;
const MIN_ATTACK_WINDOW_MS = 90000;
const LAUNCH_CONE_HALF_ANGLE_DEG = 12;
const LAUNCH_CONE_RANGE_KM = 900;
const AIR_RAID_TRACK_DISTANCE_KM = 55;
const AIR_RAID_TARGET_DISTANCE_KM = 60;
const PROBABLE_TARGET_DISTANCE_KM = 82;

const fallbackThreatKinds: ThreatKind[] = ["geran2", "gerbera", "parodiya", "kh101", "kalibr", "iskander"];
const ABSTRACT_KM_PER_DEGREE = 85;

const threatFlightDurationMs: Record<ThreatKind, [number, number]> = {
  drone: [120000, 180000],
  ballistic: [20000, 40000],
  cruise: [70000, 110000],
  decoy: [120000, 180000],
  combined: [70000, 110000],
  saturation: [130000, 190000],
  geran2: [120000, 180000],
  gerbera: [120000, 180000],
  parodiya: [120000, 180000],
  kh101: [70000, 110000],
  kalibr: [70000, 110000],
  iskander: [20000, 40000],
};

const threatBaseDifficulty: Record<ThreatKind, number> = {
  drone: 24,
  ballistic: 54,
  cruise: 42,
  decoy: 18,
  combined: 56,
  saturation: 48,
  geran2: 26,
  gerbera: 18,
  parodiya: 14,
  kh101: 44,
  kalibr: 42,
  iskander: 58,
};

const threatDamage: Record<ThreatKind, number> = {
  drone: 3,
  ballistic: 9,
  cruise: 7,
  decoy: 0,
  combined: 7,
  saturation: 3,
  geran2: 3,
  gerbera: 1,
  parodiya: 0,
  kh101: 7,
  kalibr: 7,
  iskander: 9,
};

const threatReward: Record<ThreatKind, number> = {
  drone: 2,
  ballistic: 15,
  cruise: 10,
  decoy: 1,
  combined: 10,
  saturation: 2,
  geran2: 2,
  gerbera: 1,
  parodiya: 1,
  kh101: 10,
  kalibr: 10,
  iskander: 15,
};

function cloneState(state: GameState): GameState {
  return {
    ...state,
    resources: { ...state.resources },
    cities: state.cities.map((city) => ({ ...city })),
    infrastructure: state.infrastructure.map((node) => ({ ...node })),
    launchSectors: state.launchSectors.map((sector) => ({
      ...sector,
      targetCoordinates: sector.targetCoordinates ? { ...sector.targetCoordinates } : undefined,
      lastLaunchCoordinates: sector.lastLaunchCoordinates ? { ...sector.lastLaunchCoordinates } : undefined,
      threats: [...sector.threats],
    })),
    units: state.units.map((unit) => ({ ...unit })),
    batteries: state.batteries.map((battery) => ({ ...battery, position: { ...battery.position } })),
    storedBatteries: (state.storedBatteries || []).map((battery) => ({ ...battery, position: { ...battery.position } })),
    carriers: state.carriers.map((carrier) => ({ ...carrier, position: { ...carrier.position } })),
    pendingLaunches: state.pendingLaunches.map((launch) => ({ ...launch, origin: { ...launch.origin } })),
    liveThreats: state.liveThreats.map((threat) => ({
      ...threat,
      origin: { ...threat.origin },
      target: { ...threat.target },
      lastKnownPosition: threat.lastKnownPosition ? { ...threat.lastKnownPosition } : undefined,
    })),
    interceptorShots: state.interceptorShots.map((shot) => ({ ...shot, from: { ...shot.from }, to: { ...shot.to } })),
    impactMarkers: state.impactMarkers.map((marker) => ({ ...marker, position: { ...marker.position } })),
    log: state.log.map((entry) => ({ ...entry })),
    forecast: { ...state.forecast },
    currentAttackPlan: state.currentAttackPlan ? { ...state.currentAttackPlan, targetPriorities: [...state.currentAttackPlan.targetPriorities], threatMix: [...state.currentAttackPlan.threatMix] } : null,
    campaignAttackSchedule: state.campaignAttackSchedule ? { ...state.campaignAttackSchedule, directions: [...state.campaignAttackSchedule.directions] } : null,
    attackPlanHistory: state.attackPlanHistory.map((plan) => ({ ...plan, targetPriorities: [...plan.targetPriorities], threatMix: [...plan.threatMix] })),
    cycleSnapshot: state.cycleSnapshot ? {
      ...state.cycleSnapshot,
      resources: { ...state.cycleSnapshot.resources },
      cities: state.cycleSnapshot.cities.map((city) => ({ ...city })),
      infrastructure: state.cycleSnapshot.infrastructure.map((node) => ({ ...node })),
      batteries: state.cycleSnapshot.batteries.map((battery) => ({ ...battery })),
    } : null,
    afterActionReports: state.afterActionReports.map((report) => ({ ...report })),
    planningActions: {
      selected: [...state.planningActions.selected],
      cooldowns: { ...state.planningActions.cooldowns },
      usageCounts: { ...state.planningActions.usageCounts },
      pendingAid: state.planningActions.pendingAid.map((aid) => ({ ...aid })),
    },
    logistics: {
      nodes: state.logistics.nodes.map((node) => ({ ...node, position: { ...node.position } })),
      routes: state.logistics.routes.map((route) => ({ ...route, from: { ...route.from }, to: { ...route.to } })),
      citySupply: { ...state.logistics.citySupply },
      unitSupply: { ...state.logistics.unitSupply },
      resupplyDelayDays: state.logistics.resupplyDelayDays,
      ammoRecoveryMultiplier: state.logistics.ammoRecoveryMultiplier,
      repairRecoveryMultiplier: state.logistics.repairRecoveryMultiplier,
    },
    placementWarning: state.placementWarning,
  };
}

export function formatClock(elapsedMs: number) {
  const nightDurationMinutes = 10 * 60;
  const simulatedMinutes = Math.min(nightDurationMinutes, Math.floor((elapsedMs / 1000 / 60) * 8));
  const clockMinutes = (20 * 60 + simulatedMinutes) % (24 * 60);
  const hours = Math.floor(clockMinutes / 60);
  const minutes = clockMinutes % 60;
  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
}

function pushLog(
  entries: IntelEntry[],
  elapsedMs: number,
  title: string,
  body: string,
  tone: IntelEntry["tone"],
  metadata: Pick<IntelEntry, "eventType" | "locationLabel"> = {},
) {
  entries.unshift({
    id: `${Math.floor(elapsedMs)}-${entries.length}-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
    time: formatClock(elapsedMs),
    title,
    body,
    tone,
    ...metadata,
  });
  entries.splice(30);
}

function nearestCityId(state: GameState, position: Coordinates): CityId {
  let nearest = state.cities[0];
  let nearestScore = Infinity;
  for (const city of state.cities) {
    const score = Math.abs(city.coordinates.lat - position.lat) + Math.abs(city.coordinates.lng - position.lng);
    if (score < nearestScore) {
      nearest = city;
      nearestScore = score;
    }
  }
  return nearest.id;
}

function batteryTier(unit: ReturnType<typeof getUnitDefinition>): DefenseBattery["coverageTier"] {
  if (unit.outerRangeKm >= 75) return "III";
  if (unit.outerRangeKm >= 35) return "II";
  return "I";
}

function coverageRadiusFromUnit(unit: ReturnType<typeof getUnitDefinition>) {
  if (unit.kind === "radar") return 100 / ABSTRACT_KM_PER_DEGREE;
  return clamp(unit.outerRangeKm / ABSTRACT_KM_PER_DEGREE, 0.1, 2.1);
}

export function placeBattery(state: GameState, kind: UnitKind, position: Coordinates, random: () => number): GameState {
  const scenario = getScenario(state.scenarioId);
  const unit = getUnitDefinition(kind);
  if (state.status !== "active" || state.resources.budget < unit.cost || !scenario.allowedUnits.includes(kind)) return state;

  const next = cloneState(state);
  const placement = validateBatteryPlacement(kind, position, next.cities);
  if (!placement.allowed) {
    next.placementWarning = placement.reason || "Розміщення заборонене умовами сценарію.";
    pushLog(next.log, next.elapsedMs, "Розміщення неможливе", next.placementWarning, "warning");
    return next;
  }
  const tier = batteryTier(unit);
  next.resources.budget = clamp(next.resources.budget - unit.cost, 0, 999);
  const battery: DefenseBattery = {
    id: createId("battery", Math.floor(next.elapsedMs), random),
    kind,
    position: { ...position },
    coverageTier: tier,
    coverageRadius: coverageRadiusFromUnit(unit),
    readiness: unit.readiness,
    fatigue: 8,
    daysSinceMaintenance: 0,
    lastAction: "placed",
    lastEngagementResult: unit.engagementMode === "detect" ? "tracking only" : "ready",
    status: "ready",
    supplyStatus: "strained",
    cooldownMs: next.planningActions.selected.includes("rapid-redeployment") ? 900 : 0,
    reloadRemainingMs: 0,
    currentAmmo: unit.ammoCapacity,
    assignedCityId: nearestCityId(next, position),
  };
  if (next.planningActions.selected.includes("rapid-redeployment")) {
    applyRedeployFatigue(battery);
  }
  next.batteries.push(battery);
  next.placementWarning = null;
  next.logistics = buildLogisticsState(next);
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
  next.logistics = buildLogisticsState(next);
  pushLog(next.log, next.elapsedMs, `${unit.shortName} Recalled`, "A defense unit was recalled and partial budget was recovered.", "info");
  return next;
}

export function moveBatteryToStorage(state: GameState, batteryId: string): GameState {
  const next = cloneState(state);
  const battery = next.batteries.find((item) => item.id === batteryId);
  if (!battery) return next;
  const unit = getUnitDefinition(battery.kind);
  next.batteries = next.batteries.filter((item) => item.id !== batteryId);
  next.storedBatteries.push({ ...battery, position: { ...battery.position }, lastAction: "stored" });
  next.placementWarning = null;
  next.logistics = buildLogisticsState(next);
  pushLog(next.log, next.elapsedMs, `${unit.shortName} переміщено на склад`, "Одиницю знято з позиції без повернення коштів.", "info");
  return next;
}

export function deployStoredBattery(state: GameState, batteryId: string, position: Coordinates): GameState {
  const next = cloneState(state);
  const battery = next.storedBatteries.find((item) => item.id === batteryId);
  if (!battery || next.status !== "active") return next;
  const scenario = getScenario(next.scenarioId);
  const unit = getUnitDefinition(battery.kind);
  if (!scenario.allowedUnits.includes(battery.kind)) return next;
  const placement = validateBatteryPlacement(battery.kind, position, next.cities);
  if (!placement.allowed) {
    next.placementWarning = placement.reason || "Розміщення заборонене умовами сценарію.";
    pushLog(next.log, next.elapsedMs, "Розміщення неможливе", next.placementWarning, "warning");
    return next;
  }
  next.storedBatteries = next.storedBatteries.filter((item) => item.id !== batteryId);
  next.batteries.push({
    ...battery,
    position: { ...position },
    assignedCityId: nearestCityId(next, position),
    lastAction: "redeployed from storage",
  });
  next.placementWarning = null;
  next.logistics = buildLogisticsState(next);
  pushLog(next.log, next.elapsedMs, `${unit.shortName} повернуто зі складу`, `${unit.name} безкоштовно розміщено на новій позиції.`, "success");
  return next;
}

export function setBatteryMaintenance(state: GameState, batteryId: string): GameState {
  const next = cloneState(state);
  const battery = next.batteries.find((item) => item.id === batteryId);
  if (!battery || battery.status === "maintenance") return next;
  enterMaintenance(battery);
  pushLog(next.log, next.elapsedMs, "Maintenance Assigned", "A defense unit entered one abstract cycle of accelerated recovery.", "info");
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

function abstractDistanceKm(left: Coordinates, right: Coordinates) {
  return abstractDistance(left, right) * ABSTRACT_KM_PER_DEGREE;
}

function mapDistanceKm(left: Coordinates, right: Coordinates) {
  const latKm = (left.lat - right.lat) * 111;
  const avgLat = ((left.lat + right.lat) / 2 * Math.PI) / 180;
  const lngKm = (left.lng - right.lng) * 111 * Math.max(0.35, Math.cos(avgLat));
  return Math.sqrt(latKm * latKm + lngKm * lngKm);
}

function bearingDeg(from: Coordinates, to: Coordinates) {
  const lat1 = (from.lat * Math.PI) / 180;
  const lat2 = (to.lat * Math.PI) / 180;
  const dLng = ((to.lng - from.lng) * Math.PI) / 180;
  const y = Math.sin(dLng) * Math.cos(lat2);
  const x = Math.cos(lat1) * Math.sin(lat2) - Math.sin(lat1) * Math.cos(lat2) * Math.cos(dLng);
  return (Math.atan2(y, x) * 180 / Math.PI + 360) % 360;
}

function angleDeltaDeg(left: number, right: number) {
  return Math.abs(((left - right + 540) % 360) - 180);
}

function stableHash(value: string) {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0;
  }
  return hash;
}

function cityInLaunchCone(city: Coordinates, sector: LaunchSector) {
  if (sector.targetHeadingDeg === undefined) return false;
  const center = launchSectorCenter(sector);
  const distance = mapDistanceKm(center, city);
  if (distance > LAUNCH_CONE_RANGE_KM) return false;
  return angleDeltaDeg(bearingDeg(center, city), sector.targetHeadingDeg) <= LAUNCH_CONE_HALF_ANGLE_DEG;
}

function activeLaunchCorridors(state: GameState) {
  return state.launchSectors.filter((sector) =>
    (sector.state === "warning" || sector.state === "launching")
      && sector.targetHeadingDeg !== undefined
  );
}

function isDroneClass(kind: ThreatKind) {
  return kind === "drone" || kind === "decoy" || kind === "saturation" || kind === "geran2" || kind === "gerbera" || kind === "parodiya";
}

function isMissileClass(kind: ThreatKind) {
  return kind === "ballistic" || kind === "cruise" || kind === "combined" || kind === "kh101" || kind === "kalibr" || kind === "iskander";
}

function pickLaunchSector(sectors: LaunchSector[], kind: ThreatKind, random: () => number): LaunchSector {
  return pickWeightedSector(sectors, kind, random);
}

function pickTargetCity(state: GameState, kind: ThreatKind, random: () => number) {
  if (kind === "decoy" || kind === "parodiya") return pick(state.cities, random);
  let selected = state.cities[0];
  let selectedScore = -Infinity;
  for (const city of state.cities) {
    const score = city.importance * 9
      + city.damage * 0.42
      + (100 - city.infrastructure) * 0.16
      + (100 - city.energy) * 0.12
      + (random() - 0.5) * 10;
    if (score > selectedScore) {
      selected = city;
      selectedScore = score;
    }
  }
  return selected;
}

function createCarrierForThreat(state: GameState, kind: ThreatKind, launchSector: LaunchSector, random: () => number) {
  if (kind !== "kh101" && kind !== "kalibr") return undefined;
  const carrier = {
    id: createId("carrier", Math.floor(state.elapsedMs), random),
    kind: kind === "kh101" ? "tu95" as const : "black-sea-ship" as const,
    position: launchSectorCenter(launchSector),
    launchSectorId: launchSector.id,
    headingDeg: kind === "kh101" ? 275 : 330,
    ttlMs: 32000,
  };
  state.carriers.push(carrier);
  return carrier.id;
}

function spawnThreat(state: GameState, random: () => number, forcedKind?: ThreatKind, forcedTargetCityId?: CityId, forcedSectorId?: string, forcedOrigin?: Coordinates): LiveThreat {
  const plan = state.currentAttackPlan;
  const kind = forcedKind || (plan ? pickThreatKindForPlan(plan, random) : pick(fallbackThreatKinds, random));
  const city = forcedTargetCityId
    ? state.cities.find((item) => item.id === forcedTargetCityId) || pickTargetCity(state, kind, random)
    : pickTargetCity(state, kind, random);
  const launchSector = forcedSectorId
    ? state.launchSectors.find((sector) => sector.id === forcedSectorId && sectorSupportsThreat(sector, kind)) || pickLaunchSector(state.launchSectors, kind, random)
    : pickLaunchSector(state.launchSectors, kind, random);
  const carrierId = createCarrierForThreat(state, kind, launchSector, random);
  const durationWindow = threatFlightDurationMs[kind];
  const flightDurationMs = durationWindow[0] + random() * (durationWindow[1] - durationWindow[0]);
  const falseTrack = kind === "decoy" || kind === "parodiya" || random() < (plan?.deception || 0) * 0.045;
  const origin = forcedOrigin ? { ...forcedOrigin } : randomPointInSector(launchSector, random);
  if (SHOW_LAUNCH_DEBUG) console.debug("[Shieldline live launch]", { threatType: kind, sector: launchSector.id, point: origin });
  const heading = bearingDeg(origin, city.coordinates);
  const id = createId("live-threat", Math.floor(state.elapsedMs), random);
  const telemetry = threatTelemetryFor(kind, id);
  return {
    id,
    kind,
    status: "inbound",
    origin,
    target: city.coordinates,
    targetCityId: city.id,
    launchSectorId: launchSector.id,
    launchSectorName: launchSector.name,
    progress: 0,
    speed: 1 / flightDurationMs,
    speedKph: telemetry.speedKph,
    altitudeM: telemetry.altitudeM,
    difficulty: threatBaseDifficulty[kind] * (1 + Math.max(-0.06, Math.min(0.08, (launchSector.weight - 3) * 0.025))) + state.wavePressure * 0.13 + (plan?.intensity || 1) * 3.4,
    damage: falseTrack ? 0 : threatDamage[kind],
    confidence: falseTrack ? 14 + random() * 18 : 22 + random() * 24,
    saturation: kind === "saturation" || kind === "geran2" ? 1.25 : kind === "combined" ? 1.35 : 1,
    attackPlanId: plan?.id,
    archetype: plan?.archetype,
    isFalseTrack: falseTrack,
    plannedTargetPriority: city.name,
    headingDeg: heading,
    revealed: false,
    trackQuality: 0,
    reward: threatReward[kind],
    carrierId,
  };
}

function markLaunchSector(
  state: GameState,
  sectorId: string,
  status: NonNullable<LaunchSector["state"]>,
  durationMs: number,
  target?: { cityId: CityId; coordinates: Coordinates },
  origin?: Coordinates,
  activeThreatKind?: ThreatKind,
) {
  const sector = state.launchSectors.find((item) => item.id === sectorId);
  if (!sector) return;
  sector.state = status;
  sector.stateUntilMs = state.elapsedMs + durationMs;
  if (activeThreatKind) sector.activeThreatKind = activeThreatKind;
  if (status === "warning") sector.warningStartedAtMs = state.elapsedMs;
  if (origin) sector.lastLaunchCoordinates = { ...origin };
  if (target) {
    const center = origin || sector.lastLaunchCoordinates || launchSectorCenter(sector);
    sector.targetCityId = target.cityId;
    sector.targetCoordinates = { ...target.coordinates };
    sector.targetHeadingDeg = bearingDeg(center, target.coordinates);
  }
}

function schedulePendingLaunch(state: GameState, kind: ThreatKind, random: () => number, allowedSectorIds?: readonly string[]) {
  const city = pickTargetCity(state, kind, random);
  const allowed = allowedSectorIds?.length ? new Set(allowedSectorIds) : null;
  const compatibleSectors = allowed ? state.launchSectors.filter((sector) => allowed.has(sector.id)) : state.launchSectors;
  const launchSector = pickLaunchSector(compatibleSectors, kind, random);
  const origin = randomPointInSector(launchSector, random);
  const warningMs = kind === "iskander" ? 15000 : 0;
  if (warningMs > 0) {
    const pending: PendingLaunch = {
      id: createId("pending-launch", Math.floor(state.elapsedMs), random),
      kind,
      sectorId: launchSector.id,
      targetCityId: city.id,
      origin,
      launchesAtMs: state.elapsedMs + warningMs,
    };
    state.pendingLaunches.push(pending);
    markLaunchSector(state, launchSector.id, "warning", warningMs, { cityId: city.id, coordinates: city.coordinates }, origin, kind);
    pushLog(state.log, state.elapsedMs, "Підготовка пуску", `Зафіксовано підготовку в секторі «${launchSector.name}».`, "warning", { eventType: "launch", locationLabel: launchSector.name });
    return;
  }
  markLaunchSector(state, launchSector.id, "launching", 16000, { cityId: city.id, coordinates: city.coordinates }, origin, kind);
  state.liveThreats.push(spawnThreat(state, random, kind, city.id, launchSector.id, origin));
  pushLog(state.log, state.elapsedMs, "Пуски", `Зафіксовано пуски: ${launchSector.name}.`, "danger", { eventType: "launch", locationLabel: launchSector.name });
}

function resolvePendingLaunches(state: GameState, random: () => number) {
  const remaining: PendingLaunch[] = [];
  for (const launch of state.pendingLaunches) {
    if (launch.launchesAtMs > state.elapsedMs) {
      remaining.push(launch);
      continue;
    }
    const targetCity = state.cities.find((city) => city.id === launch.targetCityId);
    markLaunchSector(
      state,
      launch.sectorId,
      "launching",
      18000,
      targetCity ? { cityId: targetCity.id, coordinates: targetCity.coordinates } : undefined,
      launch.origin,
      launch.kind,
    );
    state.liveThreats.push(spawnThreat(state, random, launch.kind, launch.targetCityId, launch.sectorId, launch.origin));
    const launchSector = state.launchSectors.find((sector) => sector.id === launch.sectorId);
    pushLog(state.log, state.elapsedMs, "Ракетний пуск", "Підготовлена балістична ціль увійшла в повітряний простір.", "danger", { eventType: "launch", locationLabel: launchSector?.name || "невідомий напрямок" });
  }
  state.pendingLaunches = remaining;
}

function updateLaunchSectors(state: GameState) {
  for (const sector of state.launchSectors) {
    if (sector.state && sector.state !== "idle" && sector.stateUntilMs && sector.stateUntilMs <= state.elapsedMs) {
      if (sector.state === "launching") {
        sector.state = "cooldown";
        sector.stateUntilMs = state.elapsedMs + 16000;
      } else {
        sector.state = "idle";
        sector.stateUntilMs = undefined;
        sector.targetCityId = undefined;
        sector.targetCoordinates = undefined;
        sector.targetHeadingDeg = undefined;
        sector.lastLaunchCoordinates = undefined;
        sector.activeThreatKind = undefined;
      }
    }
  }
}

function maybeSpawnThreat(state: GameState, deltaMs: number, random: () => number) {
  if (state.cyclePhase !== "attack" || state.liveThreats.length >= MAX_LIVE_THREATS) return;
  const scenario = getScenario(state.scenarioId);
  if (scenario.pacingProfile === "guided-three-stage") {
    const schedule = state.campaignAttackSchedule || createGuidedCampaignSchedule(state.cycleStartedAtMs, random);
    state.campaignAttackSchedule = schedule;
    const phaseElapsed = state.elapsedMs - state.cycleStartedAtMs;
    const currentStage = guidedStageForElapsed(phaseElapsed);
    if (currentStage >= 3 || schedule.ballisticLaunched) return;
    if (currentStage > schedule.stageIndex) {
      schedule.stageIndex = currentStage;
      schedule.stageLaunchCount = 0;
      schedule.nextLaunchAtMs = Math.max(state.elapsedMs, state.cycleStartedAtMs + currentStage * 60_000);
    }
    if (state.elapsedMs < schedule.nextLaunchAtMs || schedule.stageLaunchCount >= guidedStageLaunchCount(schedule.stageIndex)) return;
    const direction = schedule.directions[schedule.stageIndex];
    const kind = guidedThreatKind(schedule.stageIndex, schedule.stageLaunchCount, direction, random);
    schedulePendingLaunch(state, kind, random, sectorIdsForDirection(direction));
    schedule.stageLaunchCount += 1;
    schedule.ballisticLaunched = kind === "iskander";
    schedule.nextLaunchAtMs = state.elapsedMs + nextGuidedLaunchDelayMs(random);
    return;
  }
  const plan = state.currentAttackPlan;
  const pressure = 0.000035 + state.wavePressure * 0.00000055 + (plan?.intensity || 1) * 0.000018;
  if (random() < pressure * deltaMs) {
    const kind = plan ? pickThreatKindForPlan(plan, random) : pick(fallbackThreatKinds, random);
    schedulePendingLaunch(state, kind, random);
    pushLog(state.log, state.elapsedMs, "Track Warning", `${plan?.eventText || "Uncertain inbound track appeared on the tactical map."}`, "warning");
  }
}

function detectThreats(state: GameState, random: () => number, shouldScan: boolean) {
  const highAlert = state.planningActions.selected.includes("high-alert");
  const intelFocus = state.planningActions.selected.includes("intelligence-focus");
  for (const threat of state.liveThreats) {
    const position = threatPosition(threat);
    const wasRevealed = threat.revealed;
    let bestRadarChance = 0;
    for (const battery of state.batteries) {
      const unit = getUnitDefinition(battery.kind);
      if (unit.engagementMode !== "detect" || battery.status === "maintenance") continue;
      const rangeKm = distanceKm(position, battery.position);
      if (rangeKm > 100) continue;
      const bandChance = rangeKm <= 50 ? 95 : rangeKm <= 75 ? 75 : 40;
      const statusPenalty = battery.status === "exhausted" ? 0.45 : battery.status === "strained" ? 0.72 : 1;
      const readinessFactor = 0.58 + (battery.readiness / 100) * 0.42;
      const planningBoost = (highAlert ? 8 : 0) + (intelFocus ? 6 : 0);
      const chance = clamp(bandChance * statusPenalty * readinessFactor + planningBoost - threat.difficulty * 0.08, 5, 98);
      bestRadarChance = Math.max(bestRadarChance, chance);
    }

    threat.revealed = bestRadarChance > 0;
    if (!threat.revealed) {
      if (threat.status !== "engaged") threat.status = "inbound";
      threat.trackQuality = clamp(threat.trackQuality - 0.32, 0, 100);
      continue;
    }

    if (threat.status !== "engaged") threat.status = "inbound";
    threat.lastKnownPosition = position;
    threat.headingDeg = bearingDeg(threat.origin, threat.target);
    threat.trackQuality = shouldScan
      ? clamp(bestRadarChance + (intelFocus ? 8 : 0), 18, 100)
      : clamp(threat.trackQuality - 0.04, 18, 100);

    if (shouldScan) {
      const firstContactBoost = wasRevealed ? 0 : 8 + random() * 8;
      threat.confidence = clamp(threat.confidence + (bestRadarChance / 100) * 8 + firstContactBoost + (intelFocus ? 6 : 0), 0, 100);
      if (!wasRevealed) {
        pushLog(state.log, state.elapsedMs, "Радарний контакт", `${threat.isFalseTrack ? "Ціль із низькою достовірністю" : "Ціль"} увійшла в зону радіолокаційного покриття.`, "info", { eventType: "detection", locationLabel: threat.targetCityId });
      }
    }
  }
}

function updateShots(state: GameState, deltaMs: number, random: () => number) {
  const resolvedThreatIds = new Set<string>();
  const threatById = new Map(state.liveThreats.map((threat) => [threat.id, threat]));
  const nextShots: InterceptorShot[] = [];
  for (const shot of state.interceptorShots) {
    const nextProgress = shot.progress + shot.speed * deltaMs;
    if (nextProgress >= 1) {
      const threat = threatById.get(shot.threatId);
      if (threat) {
        threat.status = "intercepted";
        resolvedThreatIds.add(threat.id);
        state.interceptions += 1;
        state.resources.budget = clamp(state.resources.budget + threat.reward, 0, 999);
        state.impactMarkers.push({
          id: createId("intercept", Math.floor(state.elapsedMs), random),
          position: threatPosition(threat),
          tone: "intercept",
          ttlMs: 1800,
        });
        pushLog(state.log, state.elapsedMs, "Intercept Confirmed", `A defense unit neutralized ${threat.kind}. Reward +${threat.reward} mln UAH.`, "success");
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

function hasLocalAmmo(unit: ReturnType<typeof getUnitDefinition>, battery: DefenseBattery) {
  if (unit.engagementMode === "detect") return false;
  if (unit.ammoCapacity === "infinite") return true;
  return typeof battery.currentAmmo === "number" && battery.currentAmmo > 0;
}

function consumeLocalAmmo(unit: ReturnType<typeof getUnitDefinition>, battery: DefenseBattery) {
  if (unit.ammoCapacity === "infinite") {
    battery.currentAmmo = "infinite";
    return;
  }
  if (typeof battery.currentAmmo !== "number") {
    battery.currentAmmo = unit.ammoCapacity;
  }
  battery.currentAmmo = Math.max(0, battery.currentAmmo - Math.max(1, unit.salvoSize));
  if (battery.currentAmmo === 0) {
    battery.status = "reloading";
    battery.reloadRemainingMs = unit.reloadMs;
    battery.lastAction = "reloading";
    battery.lastEngagementResult = "empty - reloading";
  }
}

function setShotCooldown(battery: DefenseBattery, unit: ReturnType<typeof getUnitDefinition>, random: () => number, outerBand: boolean) {
  const bandMultiplier = outerBand ? 1.32 : 1;
  const jitter = 0.86 + random() * 0.28;
  battery.cooldownMs = Math.max(750, unit.shotCooldownMs * bandMultiplier * jitter);
}

function threatPriority(kind: ThreatKind) {
  if (kind === "iskander") return 36;
  if (kind === "kh101" || kind === "kalibr") return 24;
  if (kind === "ballistic") return 30;
  if (kind === "cruise" || kind === "combined") return 22;
  if (kind === "saturation" || kind === "geran2") return 18;
  if (kind === "drone" || kind === "gerbera") return 14;
  return 8;
}

function shotStyleForUnit(kind: UnitKind) {
  if (kind === "mvg" || kind === "boat" || kind === "gepard") return "gun" as const;
  if (kind === "drone-operators") return "drone" as const;
  if (kind === "ew") return "ew" as const;
  return "missile" as const;
}

function engagementChance(
  unit: ReturnType<typeof getUnitDefinition>,
  battery: DefenseBattery,
  threat: LiveThreat,
  distanceKm: number,
  conserveAmmo: boolean,
) {
  const base = unit.engagementChanceByThreat[threat.kind] || 0;
  if (base <= 0 || distanceKm > unit.outerRangeKm) return 0;
  const inPrimaryBand = distanceKm <= unit.primaryRangeKm;
  const bandAccuracy = inPrimaryBand ? unit.primaryAccuracy : unit.outerAccuracy;
  const statusPenalty = battery.status === "exhausted" ? 0.46 : battery.status === "strained" ? 0.74 : 1;
  const readinessFactor = 0.42 + (battery.readiness / 100) * 0.58;
  const fatiguePenalty = clamp(battery.fatigue * 0.18, 0, 18);
  const confidenceFactor = threat.confidence < 35 ? 0.72 : threat.confidence < 58 ? 0.86 : 1;
  const saturationPenalty = Math.max(0, threat.saturation - 1) * 8;
  const conservePenalty = conserveAmmo ? 7 : 0;
  return clamp(
    (base * 0.68 + bandAccuracy * 0.32) * readinessFactor * statusPenalty * confidenceFactor
      - fatiguePenalty
      - saturationPenalty
      - conservePenalty,
    0,
    98,
  );
}

function engageThreats(state: GameState, random: () => number) {
  const conserveAmmo = state.planningActions.selected.includes("conserve-ammo");
  for (const battery of state.batteries) {
    const unit = getUnitDefinition(battery.kind);
    if (
      unit.engagementMode === "detect"
      || battery.cooldownMs > 0
      || battery.status === "maintenance"
      || battery.status === "reloading"
      || !hasLocalAmmo(unit, battery)
    ) continue;
    let candidate: { threat: LiveThreat; distanceKm: number; chance: number; outerBand: boolean } | null = null;
    let candidateScore = -Infinity;
    for (const threat of state.liveThreats) {
      if (!threat.revealed || threat.status === "engaged") continue;
      if (battery.kind === "drone-operators" && !isDroneClass(threat.kind)) continue;
      const distanceKm = abstractDistanceKm(threatPosition(threat), battery.position);
      const chance = engagementChance(unit, battery, threat, distanceKm, conserveAmmo);
      if (chance <= 0) continue;
      const score = threatPriority(threat.kind) + threat.progress * 42 + chance * 0.18;
      if (score > candidateScore) {
        candidate = { threat, distanceKm, chance, outerBand: distanceKm > unit.primaryRangeKm };
        candidateScore = score;
      }
    }
    if (!candidate) continue;

    consumeLocalAmmo(unit, battery);
    setShotCooldown(battery, unit, random, candidate.outerBand);
    if (!weightedChance(candidate.chance, random)) {
      battery.lastEngagementResult = `missed ${candidate.threat.kind} (${Math.round(candidate.chance)}%)`;
      applyEngagementFatigue(battery, unit.engagementMode === "disrupt" ? 0 : unit.salvoSize, false);
      continue;
    }

    candidate.threat.status = "engaged";
    candidate.threat.confidence = clamp(candidate.threat.confidence + 18, 0, 100);
    battery.lastEngagementResult = `${unit.engagementMode === "disrupt" ? "suppressed" : "hit"} ${candidate.threat.kind} (${Math.round(candidate.chance)}%)`;
    applyEngagementFatigue(battery, unit.engagementMode === "disrupt" ? 0 : unit.salvoSize, true);
    state.interceptorShots.push({
      id: createId("shot", Math.floor(state.elapsedMs), random),
      batteryId: battery.id,
      threatId: candidate.threat.id,
      from: battery.position,
      to: threatPosition(candidate.threat),
      progress: 0,
      speed: 0.0017,
      style: shotStyleForUnit(battery.kind),
    });
    pushLog(state.log, state.elapsedMs, "Engagement", `${unit.shortName} engaged a ${candidate.threat.kind} track at ${Math.round(candidate.chance)}% confidence-adjusted chance.`, "info");
  }
}

function applyImpact(state: GameState, threat: LiveThreat, random: () => number) {
  const city = state.cities.find((item) => item.id === threat.targetCityId);
  if (!city) return;

  const damage = threat.isFalseTrack ? 0 : threat.damage;
  city.damage = clamp(city.damage + damage * 0.35);
  city.infrastructure = clamp(city.infrastructure - damage * 0.25);
  city.energy = clamp(city.energy - damage * 0.2);
  state.resources.energy = clamp(state.resources.energy - damage * 0.1);
  state.resources.morale = clamp(state.resources.morale - (city.importance * 0.5 + 0.8));
  state.impacts += 1;
  state.impactMarkers.push({ id: createId("impact", Math.floor(state.elapsedMs), random), position: city.coordinates, tone: "impact", ttlMs: 2600 });
  pushLog(state.log, state.elapsedMs, "Impact", `${city.name} was hit by an unresolved ${threat.kind} track.`, "danger");
}

function updateThreats(state: GameState, deltaMs: number, random: () => number) {
  const remaining: LiveThreat[] = [];
  for (const threat of state.liveThreats) {
    const next = { ...threat, progress: threat.progress + threat.speed * deltaMs };
    if (next.revealed) {
      next.lastKnownPosition = threatPosition(next);
      next.headingDeg = bearingDeg(next.origin, next.target);
    }
    if (next.progress >= 1) {
      applyImpact(state, next, random);
    } else {
      remaining.push(next);
    }
  }
  state.liveThreats = remaining;
}

function updateCityAlerts(state: GameState) {
  const launchCorridors = activeLaunchCorridors(state);
  const probableLaunchTargets = new Set<CityId>();
  for (const sector of launchCorridors) {
    const targetCoordinates = sector.targetCoordinates;
    const targetCityId = sector.targetCityId;
    const targetCount = 2 + (stableHash(`${sector.id}:${targetCityId || "target"}`) % 3);
    const sectorTargets = new Set<CityId>();
    const candidates = state.cities
      .filter((city) => cityInLaunchCone(city.coordinates, sector))
      .map((city) => ({
        city,
        score: (targetCoordinates ? abstractDistanceKm(city.coordinates, targetCoordinates) : 0)
          + angleDeltaDeg(bearingDeg(launchSectorCenter(sector), city.coordinates), sector.targetHeadingDeg!) * 8
          - city.importance * 2,
      }))
      .sort((left, right) => left.score - right.score);
    if (targetCityId) sectorTargets.add(targetCityId);
    for (const { city } of candidates) {
      if (sectorTargets.size >= targetCount) break;
      sectorTargets.add(city.id);
    }
    for (const cityId of sectorTargets) {
      probableLaunchTargets.add(cityId);
    }
  }

  function raiseAlert(current: NonNullable<GameState["cities"][number]["alertState"]>, next: NonNullable<GameState["cities"][number]["alertState"]>) {
    const rank = { calm: 0, "launch-corridor": 1, "probable-target": 2, "air-raid": 3 };
    return rank[next] > rank[current] ? next : current;
  }

  for (const city of state.cities) {
    let alert: NonNullable<typeof city.alertState> = "calm";
    if (launchCorridors.some((sector) => cityInLaunchCone(city.coordinates, sector))) {
      alert = raiseAlert(alert, "launch-corridor");
    }
    if (probableLaunchTargets.has(city.id)) {
      alert = raiseAlert(alert, "probable-target");
    }
    for (const threat of state.liveThreats) {
      if (!threat.revealed) continue;
      const position = threatPosition(threat);
      const trackDistance = distanceKm(city.coordinates, position);
      const targetDistance = distanceKm(city.coordinates, threat.target);
      if (
        trackDistance <= AIR_RAID_TRACK_DISTANCE_KM
        || (isMissileClass(threat.kind) && threat.progress >= 0.62 && targetDistance <= AIR_RAID_TARGET_DISTANCE_KM)
        || (isDroneClass(threat.kind) && trackDistance <= AIR_RAID_TRACK_DISTANCE_KM)
      ) {
        alert = raiseAlert(alert, "air-raid");
        break;
      }
      if (targetDistance <= PROBABLE_TARGET_DISTANCE_KM || trackDistance <= PROBABLE_TARGET_DISTANCE_KM) {
        alert = raiseAlert(alert, "probable-target");
      }
    }
    city.alertState = alert;
  }
}

function updateResourcesAndTimers(state: GameState, deltaMs: number) {
  state.logistics = buildLogisticsState(state);
  for (const battery of state.batteries) {
    const unit = getUnitDefinition(battery.kind);
    if (battery.currentAmmo === undefined || battery.currentAmmo === null) {
      battery.currentAmmo = unit.ammoCapacity;
    }
    if (battery.reloadRemainingMs === undefined || battery.reloadRemainingMs === null) {
      battery.reloadRemainingMs = 0;
    }
    battery.cooldownMs = Math.max(0, battery.cooldownMs - deltaMs);
    if (battery.status === "reloading") {
      battery.reloadRemainingMs = Math.max(0, battery.reloadRemainingMs - deltaMs);
      if (battery.reloadRemainingMs <= 0) {
        battery.currentAmmo = unit.ammoCapacity;
        battery.lastAction = "reload complete";
        battery.lastEngagementResult = "reloaded";
        battery.status = "ready";
      }
    }
    battery.supplyStatus = state.logistics.unitSupply[battery.id] || "strained";
    recoverReadiness(battery, deltaMs, false, battery.supplyStatus);
    if (state.planningActions.selected.includes("high-alert")) {
      battery.fatigue = clamp(battery.fatigue + deltaMs * 0.00009, 0, 100);
    }
  }
  state.impactMarkers = state.impactMarkers
    .map((marker) => ({ ...marker, ttlMs: marker.ttlMs - deltaMs }))
    .filter((marker) => marker.ttlMs > 0);
  state.carriers = state.carriers
    .map((carrier) => ({ ...carrier, ttlMs: carrier.ttlMs - deltaMs }))
    .filter((carrier) => carrier.ttlMs > 0);
  state.wavePressure = clamp(state.wavePressure + deltaMs * 0.00018, 10, 100);
  state.resources.budget = clamp(state.resources.budget + deltaMs * 0.00036 * state.logistics.repairRecoveryMultiplier, 0, 999);
  state.resources.ammo = clamp(state.resources.ammo + deltaMs * 0.0002 * state.logistics.ammoRecoveryMultiplier, 0, 999);
}

function startAttackCycle(state: GameState, random: () => number) {
  const scenario = getScenario(state.scenarioId);
  state.logistics = buildLogisticsState(state);
  applyPlanningActionCosts(state);
  applyPlanningRecoveryEffects(state);
  const context = createThreatDirectorContext(state, scenario);
  const plan = chooseAttackPlan(context, random);
  state.currentAttackPlan = plan;
  state.campaignAttackSchedule = scenario.pacingProfile === "guided-three-stage"
    ? createGuidedCampaignSchedule(state.elapsedMs, random)
    : null;
  state.attackPlanHistory = [...state.attackPlanHistory, plan].slice(-8);
  state.cycleSnapshot = createCycleSnapshot(state);
  state.cyclePhase = "attack";
  state.cycleStartedAtMs = state.elapsedMs;
  pushLog(state.log, state.elapsedMs, "Threat Director", plan.eventText, plan.archetype === "combined" || plan.archetype === "saturation" ? "warning" : "info");
}

function finishAttackCycle(state: GameState) {
  if (state.cycleSnapshot) {
    const report = generateAfterActionReport(state, state.cycleSnapshot);
    state.afterActionReports = [report, ...state.afterActionReports].slice(0, 8);
    state.latestReportId = report.id;
    pushLog(state.log, state.elapsedMs, "After Action Report", report.situationSummary, report.defensePerformance.missedThreats > 0 ? "warning" : "success");
  }
  state.day += 1;
  for (const battery of state.batteries) {
    battery.daysSinceMaintenance += 1;
    if (battery.status === "maintenance") {
      battery.status = "ready";
      battery.lastAction = "maintenance complete";
    }
  }
  closePlanningDay(state);
  state.currentAttackPlan = null;
  state.campaignAttackSchedule = null;
  state.cycleSnapshot = null;
  state.cyclePhase = "planning";
  state.cycleStartedAtMs = state.elapsedMs;
}

function updateCycle(state: GameState, random: () => number) {
  const phaseElapsed = state.elapsedMs - state.cycleStartedAtMs;
  if (state.cyclePhase === "planning" && phaseElapsed >= PLANNING_WINDOW_MS) {
    startAttackCycle(state, random);
  }
  const guidedCampaign = getScenario(state.scenarioId).pacingProfile === "guided-three-stage";
  const minimumAttackWindow = guidedCampaign ? 160_000 : MIN_ATTACK_WINDOW_MS;
  const attackResolved = guidedCampaign
    ? state.liveThreats.length === 0
    : phaseElapsed >= state.cycleDurationMs || state.liveThreats.length === 0;
  if (
    state.cyclePhase === "attack"
    && phaseElapsed >= minimumAttackWindow
    && state.pendingLaunches.length === 0
    && attackResolved
  ) {
    finishAttackCycle(state);
  }
}

function evaluateLiveStatus(state: GameState) {
  const collapsedCities = state.cities.filter((city) => city.infrastructure <= 0 || city.damage >= 100).length;
  const scenario = getScenario(state.scenarioId);
  if (state.resources.morale <= 0) {
    state.status = "lost";
    state.statusReason = "National morale collapsed.";
  } else if (state.resources.energy <= 0) {
    state.status = "lost";
    state.statusReason = "Energy stability collapsed.";
  } else if (collapsedCities >= 3) {
    state.status = "lost";
    state.statusReason = "Too many cities lost essential services.";
  } else if (scenario.durationDays > 0 && state.day > scenario.durationDays) {
    state.status = "won";
    state.statusReason = "Scenario duration completed with national systems still functioning.";
  }
}

export function startAttackNow(current: GameState, random: () => number): GameState {
  if (current.status !== "active" || current.cyclePhase === "attack") return current;
  const state = cloneState(current);
  startAttackCycle(state, random);
  return state;
}

export function tickSimulation(current: GameState, deltaMs: number, random: () => number): GameState {
  if (current.status !== "active") return current;
  const state = cloneState(current);
  const safeDelta = clamp(deltaMs, 0, 10_000);
  const previousElapsedMs = state.elapsedMs;
  state.elapsedMs += safeDelta;
  updateResourcesAndTimers(state, safeDelta);
  updateLaunchSectors(state);
  updateCycle(state, random);
  resolvePendingLaunches(state, random);
  maybeSpawnThreat(state, safeDelta, random);
  detectThreats(state, random, Math.floor(previousElapsedMs / 1000) !== Math.floor(state.elapsedMs / 1000));
  engageThreats(state, random);
  updateShots(state, safeDelta, random);
  updateThreats(state, safeDelta, random);
  updateCityAlerts(state);
  evaluateLiveStatus(state);
  return state;
}

export function advanceSimulation(current: GameState, deltaMs: number, random: () => number): GameState {
  let state = current;
  let remaining = clamp(deltaMs, 0, 180_000);
  const stepSizeMs = getScenario(current.scenarioId).pacingProfile === "guided-three-stage" ? 1_000 : 10_000;
  while (remaining > 0 && state.status === "active") {
    const step = Math.min(stepSizeMs, remaining);
    state = tickSimulation(state, step, random);
    remaining -= step;
  }
  return state;
}
