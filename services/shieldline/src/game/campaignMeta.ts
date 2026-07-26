import { CAMPAIGN_TUTORIAL_ASSET_ACTION, campaignKillRewards, campaignResupplyCosts, getCampaignMission, getCampaignRoute, missionTargetCount } from "../data/campaignPlan";
import { getUnitDefinition } from "../data/units";
import type { CampaignMissionResult, CampaignSpawnEvent, CampaignState, Coordinates, DefenseBattery, GameState, ThreatKind, UnitKind } from "../types/game";
import { clamp } from "./math";

const KM_PER_DEGREE = 100;

function copyPoint(point: Coordinates): Coordinates { return { lat: point.lat, lng: point.lng }; }
function pointDistanceKm(a: Coordinates, b: Coordinates) { return Math.hypot(a.lat - b.lat, a.lng - b.lng) * KM_PER_DEGREE; }
function interpolate(a: Coordinates, b: Coordinates, ratio: number): Coordinates { return { lat: a.lat + (b.lat - a.lat) * ratio, lng: a.lng + (b.lng - a.lng) * ratio }; }

export function buildCampaignSpawnEvents(missionIndex: number): CampaignSpawnEvent[] {
  const mission = getCampaignMission(missionIndex);
  return mission.waves.flatMap((wave, waveIndex) => Array.from({ length: wave.count }, (_, targetIndex) => {
    const routeId = wave.routeIds[targetIndex % wave.routeIds.length];
    const spread = wave.count <= 1 ? 0 : wave.spawnSpreadSec * targetIndex / (wave.count - 1);
    const merges = /merge/i.test(wave.mergeBehavior) && wave.routeIds.length > 1;
    return {
      id: `m${missionIndex}-w${waveIndex + 1}-t${targetIndex + 1}`,
      dueMs: Math.round((wave.timeSeconds + spread) * 1_000),
      threatKind: wave.threatKind,
      routeId,
      groupId: `m${missionIndex}-w${waveIndex + 1}-g${Math.floor(targetIndex / Math.max(1, wave.groupSize)) + 1}`,
      mergeBehavior: wave.mergeBehavior,
      priority: wave.priority,
      targetRegion: wave.targetRegion,
      mergeRouteId: merges ? wave.routeIds[0] : undefined,
      rallyRatio: merges ? (/inner/i.test(wave.mergeBehavior) ? .6 : /hard/i.test(wave.mergeBehavior) ? .5 : .4) : undefined,
    };
  })).sort((left, right) => left.dueMs - right.dueMs || left.id.localeCompare(right.id));
}

export function createCampaignState(missionIndex = 1, wallet = 0): CampaignState {
  const mission = getCampaignMission(missionIndex);
  return {
    missionIndex,
    campaignWallet: wallet,
    campaignAmmoStock: 36,
    civilianResilience: 100,
    unlockedSystems: [...mission.unlocks],
    previousMissionResults: [],
    spawnEvents: buildCampaignSpawnEvents(missionIndex),
    spawnCursor: 0,
    missionKillReward: 0,
    missionKillsByKind: {},
    missionInterceptionsAtStart: 0,
    missionImpactsAtStart: 0,
    missionGrant: mission.grant,
    missionGrantApplied: false,
    intermission: false,
    completed: false,
    tutorialStep: 0,
    tutorialActionQueue: [],
    tutorialNextPromptAtMs: 0,
  };
}

export function unlockedCampaignMissionIndex(campaign: CampaignState | null | undefined) {
  if (!campaign) return 1;
  if (campaign.completed) return 5;
  return Math.min(5, campaign.missionIndex + (campaign.intermission ? 1 : 0));
}

export function applyCampaignMissionOpening(state: GameState) {
  if (!state.campaign) return;
  const mission = getCampaignMission(state.campaign.missionIndex);
  if (mission.index === 1) {
    addCampaignStoredBattery(state, "long-radar", { lat: 50.2, lng: 30.1 }, CAMPAIGN_TUTORIAL_ASSET_ACTION, "campaign-m1-long-radar");
    addCampaignStoredBattery(state, "mvg", { lat: 50.2, lng: 31.0 }, CAMPAIGN_TUTORIAL_ASSET_ACTION, "campaign-m1-mvg");
  }
  state.campaign.unlockedSystems = [...new Set([...state.campaign.unlockedSystems, ...mission.unlocks])];
  if (state.campaign.missionGrantApplied) return;
  state.campaign.missionGrant = mission.grant;
  state.campaign.campaignWallet = Math.max(0, state.campaign.campaignWallet + mission.grant);
  state.campaign.campaignAmmoStock = clamp(state.campaign.campaignAmmoStock + 8 + mission.index * 4, 0, 9999);
  state.resources.budget = state.campaign.campaignWallet;
  state.campaign.missionGrantApplied = true;
  state.campaign.missionInterceptionsAtStart = state.interceptions;
  state.campaign.missionImpactsAtStart = state.impacts;
  state.cycleDurationMs = mission.durationMinutes * 60_000;
}

export function recordCampaignKill(state: GameState, kind: ThreatKind, reward: number) {
  if (!state.campaign) return 0;
  const canonicalReward = campaignKillRewards[kind] ?? reward;
  const credited = Math.max(0, canonicalReward);
  state.campaign.missionKillReward += credited;
  state.campaign.missionKillsByKind[kind] = (state.campaign.missionKillsByKind[kind] || 0) + 1;
  state.campaign.campaignWallet = Math.max(0, state.campaign.campaignWallet + credited);
  state.resources.budget = state.campaign.campaignWallet;
  return credited;
}

function addLine(lines: CampaignMissionResult["rewardLines"], label: string, amount: number, kind: CampaignMissionResult["rewardLines"][number]["kind"]) {
  if (amount) lines.push({ label, amount, kind });
}

export function campaignMissionObjective(state: GameState, missionIndex = state.campaign?.missionIndex || 1) {
  const campaign = state.campaign;
  const impactLimits = [3, 6, 7, 8, 9];
  const resilienceFloors = [88, 78, 68, 55, 40];
  const impacts = campaign ? state.impacts - campaign.missionImpactsAtStart : state.impacts;
  const resilience = campaign?.civilianResilience ?? 100;
  const impactLimit = impactLimits[Math.max(0, Math.min(4, missionIndex - 1))];
  const resilienceFloor = resilienceFloors[Math.max(0, Math.min(4, missionIndex - 1))];
  const objectiveMet = impacts <= impactLimit && resilience >= resilienceFloor;
  return { objectiveMet, summary: objectiveMet ? `Завдання виконано: влучань ${impacts}/${impactLimit}, стійкість ${Math.round(resilience)}%.` : `Завдання не виконано: допустимо до ${impactLimit} влучань і стійкість не нижче ${resilienceFloor}%.` };
}

export function finalizeCampaignMission(state: GameState): CampaignMissionResult | null {
  const campaign = state.campaign;
  if (!campaign || campaign.intermission) return null;
  const mission = getCampaignMission(campaign.missionIndex);
  const interceptions = state.interceptions - campaign.missionInterceptionsAtStart;
  const impacts = state.impacts - campaign.missionImpactsAtStart;
  const totalTargets = campaign.spawnEvents.length || missionTargetCount(mission);
  const objective = campaignMissionObjective(state, campaign.missionIndex);
  const lines: CampaignMissionResult["rewardLines"] = [];
  addLine(lines, "Грант місії", mission.grant, "grant");
  addLine(lines, "Винагорода за збиті цілі", campaign.missionKillReward, "kill");
  let bonusRewards = 0;
  if (campaign.civilianResilience > 80) { bonusRewards += 5; addLine(lines, "Civilian resilience > 80%", 5, "bonus"); }
  if (campaign.civilianResilience > 90) { bonusRewards += 10; addLine(lines, "Civilian resilience > 90%", 10, "bonus"); }
  if (impacts < 3) { bonusRewards += 5; addLine(lines, "Менше 3 влучань", 5, "bonus"); }
  if (totalTargets > 0 && interceptions / totalTargets > .8) { bonusRewards += 5; addLine(lines, "Збито понад 80%", 5, "bonus"); }
  if (objective.objectiveMet) { bonusRewards += 4; addLine(lines, "Завдання місії виконано", 4, "bonus"); }
  const ballisticKills = (campaign.missionKillsByKind.iskander || 0) + (campaign.missionKillsByKind.ballistic || 0);
  if (ballisticKills > 0) { bonusRewards += 10; addLine(lines, "Збито балістичну ціль", 10, "bonus"); }

  let penaltyCosts = 0;
  if (campaign.civilianResilience < 60) { penaltyCosts += 5; addLine(lines, "Civilian resilience < 60%", -5, "penalty"); }
  if (campaign.civilianResilience < 40) { penaltyCosts += 10; addLine(lines, "Civilian resilience < 40%", -10, "penalty"); }
  const heavilyDamaged = [...state.batteries, ...state.storedBatteries].filter((battery) => battery.health < 40).length;
  if (heavilyDamaged) { penaltyCosts += heavilyDamaged * 3; addLine(lines, `${heavilyDamaged} суттєво пошкодж. систем`, -heavilyDamaged * 3, "penalty"); }
  if (impacts > 8) { penaltyCosts += 5; addLine(lines, "Більше 8 влучань", -5, "penalty"); }

  campaign.campaignWallet = Math.max(0, state.resources.budget + bonusRewards - penaltyCosts);
  state.resources.budget = campaign.campaignWallet;
  for (const battery of [...state.batteries, ...state.storedBatteries]) {
    battery.experienceLevel = Math.min(5, battery.experienceLevel + 1);
  }
  const result: CampaignMissionResult = {
    missionIndex: campaign.missionIndex,
    missionId: mission.id,
    title: mission.title,
    totalTargets,
    interceptions,
    impacts,
    killReward: campaign.missionKillReward,
    bonusRewards,
    penaltyCosts,
    walletAfterMission: campaign.campaignWallet,
    civilianResilienceAfterMission: campaign.civilianResilience,
    objectiveMet: objective.objectiveMet,
    objectiveSummary: objective.summary,
    rewardLines: lines,
  };
  campaign.previousMissionResults = [...campaign.previousMissionResults, result];
  campaign.intermission = true;
  campaign.completed = campaign.missionIndex >= 5;
  return result;
}

export function advanceCampaignMission(state: GameState): GameState {
  const campaign = state.campaign;
  if (!campaign || !campaign.intermission || campaign.completed) return state;
  const nextIndex = campaign.missionIndex + 1;
  const nextMission = getCampaignMission(nextIndex);
  campaign.missionIndex = nextIndex;
  campaign.spawnEvents = buildCampaignSpawnEvents(nextIndex);
  campaign.spawnCursor = 0;
  campaign.missionKillReward = 0;
  campaign.missionKillsByKind = {};
  campaign.missionGrant = nextMission.grant;
  campaign.missionGrantApplied = false;
  campaign.intermission = false;
  campaign.tutorialStep = 0;
  campaign.tutorialActionQueue = [];
  campaign.tutorialNextPromptAtMs = 0;
  campaign.unlockedSystems = [...new Set([...campaign.unlockedSystems, ...nextMission.unlocks])];
  state.resources.budget = campaign.campaignWallet;
  state.cyclePhase = "planning";
  state.cycleStartedAtMs = state.elapsedMs;
  state.cycleDurationMs = nextMission.durationMinutes * 60_000;
  state.currentAttackPlan = null;
  state.campaignAttackSchedule = null;
  state.liveThreats = [];
  state.pendingLaunches = [];
  state.engagementEvents = [];
  state.impactMarkers = [];
  state.status = "active";
  state.statusReason = "";
  state.latestReportId = null;
  applyCampaignMissionOpening(state);
  return state;
}

export function addCampaignStoredBattery(state: GameState, kind: UnitKind, position: Coordinates, lastAction: string, id: string) {
  if (!state.campaign || state.storedBatteries.some((battery) => battery.id === id) || state.batteries.some((battery) => battery.id === id)) return false;
  const unit = getUnitDefinition(kind);
  const coverageTier: DefenseBattery["coverageTier"] = unit.outerRangeKm >= 75 ? "III" : unit.outerRangeKm >= 35 ? "II" : "I";
  state.storedBatteries.push({
    id,
    kind,
    position: { ...position },
    coverageTier,
    coverageRadius: clamp(unit.outerRangeKm / 85, .1, 2.1),
    readiness: unit.readiness,
    fatigue: 0,
    daysSinceMaintenance: 0,
    lastAction,
    lastEngagementResult: "awaiting tutorial deployment",
    status: "ready",
    supplyStatus: "well-supplied",
    cooldownMs: 0,
    reloadRemainingMs: 0,
    currentAmmo: unit.ammoCapacity,
    missionReserve: unit.missionReserveCapacity,
    manualOverrideTargets: [],
    assignedCityId: "kyiv",
    health: 100,
    experienceLevel: 0,
    createdAtMission: 1,
    lastMovedMission: 0,
  });
  return true;
}

export function accelerateCampaignSchedule(state: GameState, overrideGapMs?: number) {
  const campaign = state.campaign;
  if (!campaign || state.cyclePhase !== "attack" || state.liveThreats.length || state.pendingLaunches.length) return 0;
  const nextEvent = campaign.spawnEvents[campaign.spawnCursor];
  if (!nextEvent) return 0;
  const phaseElapsedMs = state.elapsedMs - state.cycleStartedAtMs;
  const gapByMissionMs = [0, 8_000, 12_000, 14_000, 16_000, 18_000];
  const standardGapMs = overrideGapMs ?? gapByMissionMs[campaign.missionIndex] ?? 18_000;
  const ballisticLeadMs = nextEvent.threatKind === "iskander" || nextEvent.threatKind === "ballistic" ? 25_000 : 0;
  const cruiseLeadMs = ["kh101", "kalibr", "cruise"].includes(nextEvent.threatKind) ? 20_000 : 0;
  const firstMissionReinforcementLeadMs = campaign.missionIndex === 1 && nextEvent.threatKind === "kh101" && nextEvent.routeId === "R32" ? 45_000 : 0;
  const desiredDueMs = phaseElapsedMs + Math.max(standardGapMs, ballisticLeadMs, cruiseLeadMs, firstMissionReinforcementLeadMs);
  if (nextEvent.dueMs <= desiredDueMs) return 0;
  const shiftMs = nextEvent.dueMs - desiredDueMs;
  for (let index = campaign.spawnCursor; index < campaign.spawnEvents.length; index += 1) {
    campaign.spawnEvents[index].dueMs = Math.max(desiredDueMs, campaign.spawnEvents[index].dueMs - shiftMs);
  }
  return shiftMs;
}

function chaikin(points: Coordinates[]) {
  if (points.length < 3) return points.map(copyPoint);
  const result = [copyPoint(points[0])];
  for (let index = 0; index < points.length - 1; index += 1) {
    result.push(interpolate(points[index], points[index + 1], .25), interpolate(points[index], points[index + 1], .75));
  }
  result.push(copyPoint(points.at(-1)!));
  return result;
}

function samplePolyline(points: Coordinates[], count: number) {
  const segmentLengths = points.slice(1).map((point, index) => pointDistanceKm(points[index], point));
  const total = segmentLengths.reduce((sum, length) => sum + length, 0);
  const sampled: Coordinates[] = [];
  for (let sampleIndex = 0; sampleIndex < count; sampleIndex += 1) {
    let distance = total * sampleIndex / Math.max(1, count - 1);
    let segmentIndex = 0;
    while (segmentIndex < segmentLengths.length - 1 && distance > segmentLengths[segmentIndex]) {
      distance -= segmentLengths[segmentIndex];
      segmentIndex += 1;
    }
    sampled.push(interpolate(points[segmentIndex], points[segmentIndex + 1], segmentLengths[segmentIndex] ? distance / segmentLengths[segmentIndex] : 0));
  }
  return sampled;
}

function routeFromLaunchOrigin(points: readonly Coordinates[], launchOrigin?: Coordinates) {
  if (!launchOrigin || points.length < 2) return points.map(copyPoint);
  const latitudeShift = launchOrigin.lat - points[0].lat;
  const longitudeShift = launchOrigin.lng - points[0].lng;
  return points.map((point, index) => {
    const influence = 1 - index / (points.length - 1);
    return index === 0
      ? copyPoint(launchOrigin)
      : { lat: point.lat + latitudeShift * influence, lng: point.lng + longitudeShift * influence };
  });
}

export function generateCampaignRoute(event: CampaignSpawnEvent, random: () => number, launchOrigin?: Coordinates): Coordinates[] {
  const route = getCampaignRoute(event.routeId);
  if (!route) return [];
  const baseWaypoints = routeFromLaunchOrigin(route.baseWaypoints, launchOrigin);
  if (route.ballistic || event.threatKind === "iskander" || event.threatKind === "ballistic") {
    const start = copyPoint(baseWaypoints[0]);
    const end = copyPoint(baseWaypoints.at(-1)!);
    if (!launchOrigin) { start.lat += (random() - .5) * .08; start.lng += (random() - .5) * .08; }
    end.lat += (random() - .5) * .025; end.lng += (random() - .5) * .025;
    return [start, end];
  }
  const cruise = event.threatKind === "kh101" || event.threatKind === "kalibr" || event.threatKind === "cruise";
  const decoy = event.threatKind === "parodiya" || event.threatKind === "decoy";
  const minTurns = cruise ? 3 : 2;
  const maxTurns = cruise || decoy ? 6 : 5;
  const routeLength = baseWaypoints.slice(1).reduce((sum, point, index) => sum + pointDistanceKm(baseWaypoints[index], point), 0);
  const turnCount = Math.max(minTurns, Math.min(maxTurns, Math.round(routeLength / 175) - 1));
  let points = samplePolyline(baseWaypoints, turnCount + 2);
  points = points.map((point, index) => {
    if (index === 0 || index === points.length - 1) return copyPoint(point);
    const previous = points[index - 1];
    const next = points[index + 1];
    const length = Math.hypot(next.lat - previous.lat, next.lng - previous.lng) || 1;
    const lateral = (.05 + random() * .14) * (random() < .5 ? -1 : 1);
    return { lat: point.lat - (next.lng - previous.lng) / length * lateral, lng: point.lng + (next.lat - previous.lat) / length * lateral };
  });
  if (event.mergeRouteId && event.mergeRouteId !== event.routeId) {
    const mergeRoute = getCampaignRoute(event.mergeRouteId);
    if (mergeRoute) {
      const canonical = samplePolyline(routeFromLaunchOrigin(mergeRoute.baseWaypoints, launchOrigin), points.length);
      const ratio = event.rallyRatio || .45;
      const rallyIndex = Math.max(1, Math.min(points.length - 2, Math.round(ratio * (points.length - 1))));
      points = points.map((point, index) => index >= rallyIndex ? copyPoint(canonical[index]) : point);
    }
  }
  return samplePolyline(chaikin(points), points.length);
}

function orientation(a: Coordinates, b: Coordinates, c: Coordinates) { return Math.sign((b.lng - a.lng) * (c.lat - b.lat) - (b.lat - a.lat) * (c.lng - b.lng)); }
export function routeHasSelfIntersection(points: Coordinates[]) {
  for (let a = 0; a < points.length - 1; a += 1) for (let b = a + 2; b < points.length - 1; b += 1) {
    if (a === 0 && b === points.length - 2) continue;
    if (orientation(points[a], points[a + 1], points[b]) !== orientation(points[a], points[a + 1], points[b + 1]) && orientation(points[b], points[b + 1], points[a]) !== orientation(points[b], points[b + 1], points[a + 1])) return true;
  }
  return false;
}

export function campaignRedeployCost(_kind: UnitKind) { return 1; }
export function campaignRepairCost(battery: DefenseBattery) { const unit = getUnitDefinition(battery.kind); return Math.max(1, Math.ceil(unit.cost * ((100 - battery.health) / 100) * .25)); }
export function campaignResupplyCost(kind: UnitKind, portion: .5 | 1 = .5) { return Math.ceil((campaignResupplyCosts[kind] || 0) * portion * 10) / 10; }

export function serviceCampaignBattery(state: GameState, batteryId: string, action: "repair" | "resupply", portion: .5 | 1 = .5): GameState {
  if (!state.campaign || !state.campaign.intermission) return state;
  const battery = [...state.batteries, ...state.storedBatteries].find((item) => item.id === batteryId);
  if (!battery) return state;
  const unit = getUnitDefinition(battery.kind);
  const reserveCapacity = unit.missionReserveCapacity === "infinite" ? 0 : Number(unit.missionReserveCapacity);
  const reserveNow = battery.missionReserve === "infinite" ? reserveCapacity : Number(battery.missionReserve || 0);
  const requestedAmmo = action === "resupply" ? Math.min(Math.ceil(reserveCapacity * portion), Math.max(0, reserveCapacity - reserveNow), state.campaign.campaignAmmoStock) : 0;
  if (action === "resupply" && requestedAmmo <= 0) {
    state.placementWarning = state.campaign.campaignAmmoStock <= 0 ? "Стратегічний запас відсутній" : "Запас місії вже заповнено";
    return state;
  }
  const cost = action === "repair"
    ? campaignRepairCost(battery)
    : Math.ceil((campaignResupplyCosts[battery.kind] || 0) * (requestedAmmo / Math.max(1, reserveCapacity)) * 10) / 10;
  if (cost <= 0 || state.campaign.campaignWallet < cost) return state;
  state.campaign.campaignWallet -= cost;
  state.resources.budget = state.campaign.campaignWallet;
  if (action === "repair") { battery.health = 100; battery.readiness = Math.max(battery.readiness, 90); }
  else {
    battery.missionReserve = reserveNow + requestedAmmo;
    state.campaign.campaignAmmoStock -= requestedAmmo;
  }
  state.placementWarning = null;
  return state;
}
