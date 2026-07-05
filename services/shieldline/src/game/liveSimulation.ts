import { getScenario } from "../data/scenarios";
import { getUnitDefinition } from "../data/units";
import { createCycleSnapshot, generateAfterActionReport } from "./afterActionReport";
import { buildLogisticsState } from "./logistics";
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
      coordinates: { ...sector.coordinates },
      supports: [...sector.supports],
    })),
    units: state.units.map((unit) => ({ ...unit })),
    batteries: state.batteries.map((battery) => ({ ...battery, position: { ...battery.position } })),
    carriers: state.carriers.map((carrier) => ({ ...carrier, position: { ...carrier.position } })),
    pendingLaunches: state.pendingLaunches.map((launch) => ({ ...launch })),
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
  entries.splice(30);
}

function nearestCityId(state: GameState, position: Coordinates): CityId {
  return state.cities
    .map((city) => ({
      cityId: city.id,
      score: Math.abs(city.coordinates.lat - position.lat) + Math.abs(city.coordinates.lng - position.lng),
    }))
    .sort((left, right) => left.score - right.score)[0].cityId;
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

export function placeBattery(state: GameState, kind: UnitKind, position: Coordinates, random: () => number = Math.random): GameState {
  const scenario = getScenario(state.scenarioId);
  const unit = getUnitDefinition(kind);
  if (state.status !== "active" || state.resources.budget < unit.cost || !scenario.allowedUnits.includes(kind)) return state;

  const next = cloneState(state);
  const placement = validateBatteryPlacement(kind, position);
  if (!placement.allowed) {
    next.placementWarning = placement.reason || "Placement blocked by control constraints.";
    pushLog(next.log, next.elapsedMs, "Placement Blocked", next.placementWarning, "warning");
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

function bearingDeg(from: Coordinates, to: Coordinates) {
  const lat1 = (from.lat * Math.PI) / 180;
  const lat2 = (to.lat * Math.PI) / 180;
  const dLng = ((to.lng - from.lng) * Math.PI) / 180;
  const y = Math.sin(dLng) * Math.cos(lat2);
  const x = Math.cos(lat1) * Math.sin(lat2) - Math.sin(lat1) * Math.cos(lat2) * Math.cos(dLng);
  return (Math.atan2(y, x) * 180 / Math.PI + 360) % 360;
}

function isDroneClass(kind: ThreatKind) {
  return kind === "drone" || kind === "decoy" || kind === "saturation" || kind === "geran2" || kind === "gerbera" || kind === "parodiya";
}

function isMissileClass(kind: ThreatKind) {
  return kind === "ballistic" || kind === "cruise" || kind === "combined" || kind === "kh101" || kind === "kalibr" || kind === "iskander";
}

function pickLaunchSector(sectors: LaunchSector[], kind: ThreatKind, random: () => number): LaunchSector {
  const matching = sectors.filter((sector) => sector.supports.includes(kind));
  if (matching.length) return pick(matching, random);
  return pick(sectors, random);
}

function pickTargetNode(state: GameState, kind: ThreatKind, random: () => number) {
  const plan = state.currentAttackPlan;
  const preferred = plan
    ? state.infrastructure.filter((node) => plan.targetPriorities.includes(node.kind))
    : [];
  const pool = preferred.length ? preferred : state.infrastructure;
  if (kind === "decoy" || kind === "parodiya") return pick(pool, random);
  return [...pool].sort((left, right) => {
    const leftCity = state.cities.find((city) => city.id === left.cityId);
    const rightCity = state.cities.find((city) => city.id === right.cityId);
    const leftScore = (left.critical ? 20 : 0) + (leftCity?.importance || 1) * 6 + (100 - left.integrity) * 0.22;
    const rightScore = (right.critical ? 20 : 0) + (rightCity?.importance || 1) * 6 + (100 - right.integrity) * 0.22;
    return rightScore - leftScore + (random() - 0.5) * 10;
  })[0];
}

function createCarrierForThreat(state: GameState, kind: ThreatKind, launchSector: LaunchSector, random: () => number) {
  if (kind !== "kh101" && kind !== "kalibr") return undefined;
  const carrier = {
    id: createId("carrier", Math.floor(state.elapsedMs), random),
    kind: kind === "kh101" ? "tu95" as const : "black-sea-ship" as const,
    position: launchSector.coordinates,
    launchSectorId: launchSector.id,
    headingDeg: kind === "kh101" ? 275 : 330,
    ttlMs: 32000,
  };
  state.carriers.push(carrier);
  return carrier.id;
}

function spawnThreat(state: GameState, random: () => number, forcedKind?: ThreatKind, forcedTargetNodeId?: string, forcedSectorId?: string): LiveThreat {
  const plan = state.currentAttackPlan;
  const kind = forcedKind || (plan ? pickThreatKindForPlan(plan, random) : pick(fallbackThreatKinds, random));
  const node = forcedTargetNodeId
    ? state.infrastructure.find((item) => item.id === forcedTargetNodeId) || pickTargetNode(state, kind, random)
    : pickTargetNode(state, kind, random);
  const launchSector = forcedSectorId
    ? state.launchSectors.find((sector) => sector.id === forcedSectorId) || pickLaunchSector(state.launchSectors, kind, random)
    : pickLaunchSector(state.launchSectors, kind, random);
  const carrierId = createCarrierForThreat(state, kind, launchSector, random);
  const durationWindow = threatFlightDurationMs[kind];
  const flightDurationMs = durationWindow[0] + random() * (durationWindow[1] - durationWindow[0]);
  const falseTrack = kind === "decoy" || kind === "parodiya" || random() < (plan?.deception || 0) * 0.045;
  const origin = launchSector.coordinates;
  const heading = bearingDeg(origin, node.coordinates);
  return {
    id: createId("live-threat", Math.floor(state.elapsedMs), random),
    kind,
    status: "inbound",
    origin,
    target: node.coordinates,
    targetNodeId: node.id,
    targetCityId: node.cityId,
    launchSectorId: launchSector.id,
    launchSectorName: launchSector.name,
    progress: 0,
    speed: 1 / flightDurationMs,
    difficulty: threatBaseDifficulty[kind] * launchSector.pressure + state.wavePressure * 0.13 + (plan?.intensity || 1) * 3.4,
    damage: falseTrack ? 0 : threatDamage[kind],
    detected: false,
    confidence: falseTrack ? 14 + random() * 18 : 22 + random() * 24,
    saturation: kind === "saturation" || kind === "geran2" ? 1.25 : kind === "combined" ? 1.35 : 1,
    attackPlanId: plan?.id,
    archetype: plan?.archetype,
    isFalseTrack: falseTrack,
    plannedTargetPriority: node.kind,
    headingDeg: heading,
    revealed: false,
    trackQuality: 0,
    reward: threatReward[kind],
    carrierId,
  };
}

function markLaunchSector(state: GameState, sectorId: string, status: NonNullable<LaunchSector["state"]>, durationMs: number) {
  const sector = state.launchSectors.find((item) => item.id === sectorId);
  if (!sector) return;
  sector.state = status;
  sector.stateUntilMs = state.elapsedMs + durationMs;
  if (status === "warning") sector.warningStartedAtMs = state.elapsedMs;
}

function schedulePendingLaunch(state: GameState, kind: ThreatKind, random: () => number) {
  const node = pickTargetNode(state, kind, random);
  const launchSector = pickLaunchSector(state.launchSectors, kind, random);
  const warningMs = kind === "iskander" ? 15000 : 0;
  if (warningMs > 0) {
    const pending: PendingLaunch = {
      id: createId("pending-launch", Math.floor(state.elapsedMs), random),
      kind,
      sectorId: launchSector.id,
      targetNodeId: node.id,
      launchesAtMs: state.elapsedMs + warningMs,
    };
    state.pendingLaunches.push(pending);
    markLaunchSector(state, launchSector.id, "warning", warningMs);
    pushLog(state.log, state.elapsedMs, "Launch Warning", `${launchSector.name} shows abstract OTRK launch preparation.`, "warning");
    return;
  }
  markLaunchSector(state, launchSector.id, "launching", 8000);
  state.liveThreats.push(spawnThreat(state, random, kind, node.id, launchSector.id));
}

function resolvePendingLaunches(state: GameState, random: () => number) {
  const remaining: PendingLaunch[] = [];
  for (const launch of state.pendingLaunches) {
    if (launch.launchesAtMs > state.elapsedMs) {
      remaining.push(launch);
      continue;
    }
    markLaunchSector(state, launch.sectorId, "launching", 9000);
    state.liveThreats.push(spawnThreat(state, random, launch.kind, launch.targetNodeId, launch.sectorId));
    pushLog(state.log, state.elapsedMs, "Missile Launch", "A prepared ballistic launch entered the battlespace.", "danger");
  }
  state.pendingLaunches = remaining;
}

function updateLaunchSectors(state: GameState) {
  for (const sector of state.launchSectors) {
    if (sector.state && sector.state !== "idle" && sector.stateUntilMs && sector.stateUntilMs <= state.elapsedMs) {
      if (sector.state === "launching") {
        sector.state = "cooldown";
        sector.stateUntilMs = state.elapsedMs + 12000;
      } else {
        sector.state = "idle";
        sector.stateUntilMs = undefined;
      }
    }
  }
}

function maybeSpawnThreat(state: GameState, deltaMs: number, random: () => number) {
  if (state.cyclePhase !== "attack" || state.liveThreats.length >= MAX_LIVE_THREATS) return;
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
    if (shouldScan) {
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
        threat.confidence = clamp(threat.confidence + (chance / 100) * 8, 0, 100);
        if (!weightedChance(chance, random)) continue;
        threat.detected = true;
        threat.status = "detected";
        threat.revealed = true;
        threat.lastKnownPosition = position;
        threat.headingDeg = bearingDeg(threat.origin, threat.target);
        threat.trackQuality = clamp(chance + (intelFocus ? 8 : 0), 0, 100);
        threat.confidence = clamp(threat.confidence + 18 + random() * 12 + (intelFocus ? 10 : 0), 0, 100);
        pushLog(state.log, state.elapsedMs, "Target Detected", `${threat.isFalseTrack ? "Low-confidence" : threat.kind} track revealed by radar scan.`, "info");
        break;
      }
    }
    if (threat.revealed) {
      threat.lastKnownPosition = position;
      threat.headingDeg = bearingDeg(threat.origin, threat.target);
      threat.trackQuality = clamp(threat.trackQuality - 0.06, 18, 100);
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
        state.resources.budget = clamp(state.resources.budget + threat.reward, 0, 999);
        state.impactMarkers.push({
          id: createId("intercept", Math.floor(state.elapsedMs), Math.random),
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
    const candidate = state.liveThreats
      .filter((threat) => threat.revealed && threat.status !== "engaged")
      .filter((threat) => battery.kind !== "drone-operators" || isDroneClass(threat.kind))
      .map((threat) => {
        const distanceKm = abstractDistanceKm(threatPosition(threat), battery.position);
        const chance = engagementChance(unit, battery, threat, distanceKm, conserveAmmo);
        return { threat, distanceKm, chance, outerBand: distanceKm > unit.primaryRangeKm };
      })
      .filter((entry) => entry.chance > 0)
      .sort((left, right) => {
        const leftScore = threatPriority(left.threat.kind) + left.threat.progress * 42 + left.chance * 0.18;
        const rightScore = threatPriority(right.threat.kind) + right.threat.progress * 42 + right.chance * 0.18;
        return rightScore - leftScore;
      })[0];
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

function applyImpact(state: GameState, threat: LiveThreat) {
  const node = state.infrastructure.find((item) => item.id === threat.targetNodeId);
  const city = state.cities.find((item) => item.id === threat.targetCityId);
  if (!node || !city) return;

  const damage = threat.isFalseTrack ? 0 : threat.damage;
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
    const next = { ...threat, progress: threat.progress + threat.speed * deltaMs };
    if (next.revealed) {
      next.lastKnownPosition = threatPosition(next);
      next.headingDeg = bearingDeg(next.origin, next.target);
    }
    if (next.progress >= 1) {
      applyImpact(state, next);
    } else {
      remaining.push(next);
    }
  }
  state.liveThreats = remaining;
}

function updateCityAlerts(state: GameState) {
  const missileLaunchActive = state.launchSectors.some((sector) =>
    (sector.state === "warning" || sector.state === "launching")
      && (sector.category === "ballistic" || sector.category === "carrier" || sector.category === "cruise")
  );
  for (const city of state.cities) {
    let alert: NonNullable<typeof city.alertState> = "calm";
    for (const threat of state.liveThreats) {
      if (!threat.revealed) continue;
      const position = threatPosition(threat);
      const cityDistance = distanceKm(city.coordinates, position);
      if ((isDroneClass(threat.kind) && cityDistance <= 50) || (isMissileClass(threat.kind) && missileLaunchActive)) {
        alert = "air-raid";
        break;
      }
      const targetDistance = distanceKm(city.coordinates, threat.target);
      const trackDistance = distanceKm(city.coordinates, position);
      if (targetDistance <= 70 || trackDistance <= 70) {
        alert = "probable-target";
      }
    }
    if (missileLaunchActive && alert === "calm") {
      alert = "probable-target";
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
  state.cycleSnapshot = null;
  state.cyclePhase = "planning";
  state.cycleStartedAtMs = state.elapsedMs;
}

function updateCycle(state: GameState, random: () => number) {
  const phaseElapsed = state.elapsedMs - state.cycleStartedAtMs;
  if (state.cyclePhase === "planning" && phaseElapsed >= PLANNING_WINDOW_MS) {
    startAttackCycle(state, random);
  }
  if (
    state.cyclePhase === "attack"
    && phaseElapsed >= MIN_ATTACK_WINDOW_MS
    && (phaseElapsed >= state.cycleDurationMs || state.liveThreats.length === 0)
  ) {
    finishAttackCycle(state);
  }
}

function evaluateLiveStatus(state: GameState) {
  const destroyedCritical = state.infrastructure.filter((node) => node.critical && node.integrity <= 0).length;
  const scenario = getScenario(state.scenarioId);
  if (state.resources.morale <= 0) {
    state.status = "lost";
    state.statusReason = "National morale collapsed.";
  } else if (state.resources.energy <= 0) {
    state.status = "lost";
    state.statusReason = "Energy stability collapsed.";
  } else if (destroyedCritical >= 3) {
    state.status = "lost";
    state.statusReason = "Too many critical infrastructure nodes were destroyed.";
  } else if (scenario.durationDays > 0 && state.day > scenario.durationDays) {
    state.status = "won";
    state.statusReason = "Scenario duration completed with national systems still functioning.";
  }
}

export function tickSimulation(current: GameState, deltaMs: number, random: () => number = Math.random): GameState {
  if (current.status !== "active") return current;
  const state = cloneState(current);
  const safeDelta = clamp(deltaMs, 0, 1000);
  const previousElapsedMs = state.elapsedMs;
  state.elapsedMs += safeDelta;
  updateResourcesAndTimers(state, safeDelta);
  updateLaunchSectors(state);
  updateCycle(state, random);
  resolvePendingLaunches(state, random);
  maybeSpawnThreat(state, safeDelta, random);
  detectThreats(state, random, Math.floor(previousElapsedMs / 1000) !== Math.floor(state.elapsedMs / 1000));
  engageThreats(state, random);
  updateShots(state, safeDelta);
  updateThreats(state, safeDelta);
  updateCityAlerts(state);
  evaluateLiveStatus(state);
  return state;
}
