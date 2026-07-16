import { campaignKillRewards, campaignResupplyCosts, getCampaignMission, getCampaignRoute, missionTargetCount } from "../data/campaignPlan";
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
  };
}

export function unlockedCampaignMissionIndex(campaign: CampaignState | null | undefined) {
  if (!campaign) return 1;
  if (campaign.completed) return 5;
  return Math.min(5, campaign.missionIndex + (campaign.intermission ? 1 : 0));
}

export function applyCampaignMissionOpening(state: GameState) {
  if (!state.campaign || state.campaign.missionGrantApplied) return;
  const mission = getCampaignMission(state.campaign.missionIndex);
  state.campaign.unlockedSystems = [...new Set([...state.campaign.unlockedSystems, ...mission.unlocks])];
  state.campaign.missionGrant = mission.grant;
  state.campaign.campaignWallet = clamp(state.campaign.campaignWallet + mission.grant, 0, 9999);
  state.resources.budget = state.campaign.campaignWallet;
  state.campaign.missionGrantApplied = true;
  state.campaign.missionInterceptionsAtStart = state.interceptions;
  state.campaign.missionImpactsAtStart = state.impacts;
  state.cycleDurationMs = mission.durationMinutes * 60_000;
}

export function recordCampaignKill(state: GameState, kind: ThreatKind, reward: number) {
  if (!state.campaign) return 0;
  const mission = getCampaignMission(state.campaign.missionIndex);
  const canonicalReward = campaignKillRewards[kind] ?? reward;
  const available = Math.max(0, mission.rewardCap - state.campaign.missionKillReward);
  const credited = Math.min(canonicalReward, available);
  state.campaign.missionKillReward += credited;
  state.campaign.missionKillsByKind[kind] = (state.campaign.missionKillsByKind[kind] || 0) + 1;
  state.campaign.campaignWallet = clamp(state.campaign.campaignWallet + credited, 0, 9999);
  state.resources.budget = state.campaign.campaignWallet;
  return credited;
}

function addLine(lines: CampaignMissionResult["rewardLines"], label: string, amount: number, kind: CampaignMissionResult["rewardLines"][number]["kind"]) {
  if (amount) lines.push({ label, amount, kind });
}

export function finalizeCampaignMission(state: GameState): CampaignMissionResult | null {
  const campaign = state.campaign;
  if (!campaign || campaign.intermission) return null;
  const mission = getCampaignMission(campaign.missionIndex);
  const interceptions = state.interceptions - campaign.missionInterceptionsAtStart;
  const impacts = state.impacts - campaign.missionImpactsAtStart;
  const totalTargets = missionTargetCount(mission);
  const lines: CampaignMissionResult["rewardLines"] = [];
  addLine(lines, "Грант місії", mission.grant, "grant");
  addLine(lines, `Підтверджені збиття (cap ${mission.rewardCap})`, campaign.missionKillReward, "kill");
  let bonusRewards = 0;
  if (campaign.civilianResilience > 80) { bonusRewards += 5; addLine(lines, "Civilian resilience > 80%", 5, "bonus"); }
  if (campaign.civilianResilience > 90) { bonusRewards += 10; addLine(lines, "Civilian resilience > 90%", 10, "bonus"); }
  if (impacts < 3) { bonusRewards += 5; addLine(lines, "Менше 3 влучань", 5, "bonus"); }
  if (totalTargets > 0 && interceptions / totalTargets > .8) { bonusRewards += 5; addLine(lines, "Збито понад 80%", 5, "bonus"); }
  const ballisticKills = (campaign.missionKillsByKind.iskander || 0) + (campaign.missionKillsByKind.ballistic || 0);
  if (ballisticKills > 0) { bonusRewards += 10; addLine(lines, "Збито балістичну ціль", 10, "bonus"); }

  let penaltyCosts = 0;
  if (campaign.civilianResilience < 60) { penaltyCosts += 5; addLine(lines, "Civilian resilience < 60%", -5, "penalty"); }
  if (campaign.civilianResilience < 40) { penaltyCosts += 10; addLine(lines, "Civilian resilience < 40%", -10, "penalty"); }
  const heavilyDamaged = [...state.batteries, ...state.storedBatteries].filter((battery) => battery.health < 40).length;
  if (heavilyDamaged) { penaltyCosts += heavilyDamaged * 3; addLine(lines, `${heavilyDamaged} суттєво пошкодж. систем`, -heavilyDamaged * 3, "penalty"); }
  if (impacts > 8) { penaltyCosts += 5; addLine(lines, "Більше 8 влучань", -5, "penalty"); }

  campaign.campaignWallet = clamp(state.resources.budget + bonusRewards - penaltyCosts, 0, 9999);
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
  const cost = action === "repair" ? campaignRepairCost(battery) : campaignResupplyCost(battery.kind, portion);
  if (cost <= 0 || state.campaign.campaignWallet < cost) return state;
  const unit = getUnitDefinition(battery.kind);
  state.campaign.campaignWallet -= cost;
  state.resources.budget = state.campaign.campaignWallet;
  if (action === "repair") { battery.health = 100; battery.readiness = Math.max(battery.readiness, 90); }
  else if (typeof unit.ammoCapacity === "number" && typeof battery.currentAmmo === "number") battery.currentAmmo = Math.min(unit.ammoCapacity, battery.currentAmmo + Math.ceil(unit.ammoCapacity * portion));
  return state;
}
