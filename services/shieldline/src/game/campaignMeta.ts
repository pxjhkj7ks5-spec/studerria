import { CAMPAIGN_REINFORCEMENT_ACTION, CAMPAIGN_TUTORIAL_ASSET_ACTION, campaignKillRewards, getCampaignMission, getCampaignRoute, missionTargetCount } from "../data/campaignPlan";
import { getUnitDefinition } from "../data/units";
import type { CampaignAmmoDepot, CampaignMissionResult, CampaignSpawnEvent, CampaignState, CityId, Coordinates, DefenseBattery, GameState, ThreatKind, UnitKind } from "../types/game";
import { clamp } from "./math";

const KM_PER_DEGREE = 100;
export const CAMPAIGN_DEPOT_REPAIR_COST = 12;
export const CAMPAIGN_DEPOT_REPAIR_DURATION_MS = 120_000;
export const CAMPAIGN_DEPOT_PRODUCTION_INTERVAL_MS = 45_000;
const CAMPAIGN_TRAIL_INTERVAL_SEC_BY_MISSION = [0, 0, 7, 6, 5, 4] as const;

export const campaignAmmoDepotPositions: readonly Coordinates[] = [
  { lat: 49.73, lng: 23.52 },
  { lat: 50.58, lng: 25.20 },
  { lat: 50.45, lng: 26.55 },
  { lat: 49.63, lng: 25.32 },
  { lat: 49.12, lng: 26.42 },
  { lat: 48.78, lng: 24.18 },
  { lat: 48.46, lng: 22.78 },
  { lat: 48.35, lng: 25.64 },
];

const ammoDepotTargetEventIds = new Set([
  "m1-w1-t2", "m1-w2-t2",
  "m2-w3-t2", "m2-w5-t2", "m2-w11-t2",
  "m3-w2-t2", "m3-w4-t1", "m3-w10-t2", "m3-w14-t1",
  "m4-w4-t2", "m4-w10-t1", "m4-w10-t3", "m4-w13-t1",
  "m5-w6-t2", "m5-w6-t4", "m5-w9-t2", "m5-w13-t3", "m5-w13-t6", "m5-w13-t9", "m5-w14-t3", "m5-w18-t1",
]);

function copyPoint(point: Coordinates): Coordinates { return { lat: point.lat, lng: point.lng }; }
function pointDistanceKm(a: Coordinates, b: Coordinates) { return Math.hypot(a.lat - b.lat, a.lng - b.lng) * KM_PER_DEGREE; }
function interpolate(a: Coordinates, b: Coordinates, ratio: number): Coordinates { return { lat: a.lat + (b.lat - a.lat) * ratio, lng: a.lng + (b.lng - a.lng) * ratio }; }

function stableIndex(seed: string, length: number) {
  let hash = 2166136261;
  for (let index = 0; index < seed.length; index += 1) hash = Math.imul(hash ^ seed.charCodeAt(index), 16777619);
  return (hash >>> 0) % Math.max(1, length);
}

export function createCampaignAmmoDepot(seed = "campaign-default", stock = 10): CampaignAmmoDepot {
  return {
    id: "campaign-ammo-depot",
    position: { ...campaignAmmoDepotPositions[stableIndex(seed, campaignAmmoDepotPositions.length)] },
    health: 100,
    stock: Math.max(0, stock),
    productionProgressMs: 0,
    repairRemainingMs: 0,
    stockLossApplied: false,
    producedTotal: 0,
    lostTotal: 0,
  };
}

export function buildCampaignSpawnEvents(missionIndex: number): CampaignSpawnEvent[] {
  const mission = getCampaignMission(missionIndex);
  return mission.waves.flatMap((wave, waveIndex) => Array.from({ length: wave.count }, (_, targetIndex) => {
    const trailEnabled = missionIndex >= 2 && wave.groupSize > 1;
    const trailSize = trailEnabled ? Math.min(wave.count, Math.max(2, wave.groupSize)) : 1;
    const trailIndex = trailEnabled ? Math.floor(targetIndex / trailSize) : Math.floor(targetIndex / Math.max(1, wave.groupSize));
    const trailPosition = trailEnabled ? targetIndex % trailSize : 0;
    const trailLength = trailEnabled ? Math.min(trailSize, wave.count - trailIndex * trailSize) : 1;
    const trailCount = trailEnabled ? Math.ceil(wave.count / trailSize) : 1;
    const trailIntervalSec = CAMPAIGN_TRAIL_INTERVAL_SEC_BY_MISSION[missionIndex] || 4;
    const finalTrailLength = trailEnabled ? wave.count - (trailCount - 1) * trailSize : 1;
    const finalTrailDurationSec = Math.max(0, finalTrailLength - 1) * trailIntervalSec;
    const trailStartWindowSec = Math.max(0, wave.spawnSpreadSec - finalTrailDurationSec);
    const trailStartSec = trailEnabled && trailCount > 1 ? trailStartWindowSec * trailIndex / (trailCount - 1) : 0;
    const spread = trailEnabled
      ? trailStartSec + trailPosition * trailIntervalSec
      : wave.count <= 1 ? 0 : wave.spawnSpreadSec * targetIndex / (wave.count - 1);
    const routeId = trailEnabled
      ? wave.routeIds[trailIndex % wave.routeIds.length]
      : wave.routeIds[targetIndex % wave.routeIds.length];
    const merges = /merge/i.test(wave.mergeBehavior) && wave.routeIds.length > 1;
    const id = `m${missionIndex}-w${waveIndex + 1}-t${targetIndex + 1}`;
    return {
      id,
      dueMs: Math.round((wave.timeSeconds + spread) * 1_000),
      threatKind: wave.threatKind,
      routeId,
      groupId: `m${missionIndex}-w${waveIndex + 1}-g${trailIndex + 1}`,
      ...(trailEnabled ? { trailPosition, trailLength } : {}),
      mergeBehavior: wave.mergeBehavior,
      priority: wave.priority,
      targetRegion: wave.targetRegion,
      mergeRouteId: merges ? wave.routeIds[0] : undefined,
      rallyRatio: merges ? (/inner/i.test(wave.mergeBehavior) ? .6 : /hard/i.test(wave.mergeBehavior) ? .5 : .4) : undefined,
      targetAsset: ammoDepotTargetEventIds.has(id) ? "ammo-depot" as const : undefined,
    };
  })).sort((left, right) => left.dueMs - right.dueMs || left.id.localeCompare(right.id));
}

export function createCampaignState(missionIndex = 1, wallet = 0, campaignSeed = "campaign-default"): CampaignState {
  const mission = getCampaignMission(missionIndex);
  return {
    missionIndex,
    campaignWallet: wallet,
    depot: createCampaignAmmoDepot(campaignSeed),
    civilianResilience: 100,
    unlockedSystems: [...mission.unlocks],
    previousMissionResults: [],
    lastAttemptResult: null,
    retryCheckpoint: null,
    spawnEvents: buildCampaignSpawnEvents(missionIndex),
    spawnCursor: 0,
    missionKillReward: 0,
    missionKillsByKind: {},
    missionInterceptionsAtStart: 0,
    missionImpactsAtStart: 0,
    missionGrant: mission.grant,
    missionGrantApplied: false,
    missionDepotProducedAtStart: 0,
    missionDepotLostAtStart: 0,
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
  if (mission.index === 2) {
    const granted = addCampaignStoredBattery(state, "radar", { lat: 46.4, lng: 30.4 }, CAMPAIGN_REINFORCEMENT_ACTION, "campaign-m2-medium-radar");
    if (granted) {
      const radar = state.storedBatteries.find((battery) => battery.id === "campaign-m2-medium-radar");
      if (radar) {
        radar.assignedCityId = "odesa";
        radar.lastEngagementResult = "Підкріплення для південного угруповання";
      }
    }
  }
  state.campaign.unlockedSystems = [...new Set([...state.campaign.unlockedSystems, ...mission.unlocks])];
  if (state.campaign.missionGrantApplied) return;
  state.campaign.missionGrant = mission.grant;
  state.campaign.campaignWallet = Math.max(0, state.campaign.campaignWallet + mission.grant);
  state.resources.budget = state.campaign.campaignWallet;
  state.campaign.missionGrantApplied = true;
  state.campaign.depot.stock = 10;
  for (const battery of [...state.batteries, ...state.storedBatteries]) {
    const unit = getUnitDefinition(battery.kind);
    battery.currentAmmo = unit.ammoCapacity;
    battery.missionReserve = unit.missionReserveCapacity === "infinite" ? "infinite" : 0;
    battery.reloadRemainingMs = 0;
    if (battery.status === "reloading") {
      battery.status = battery.fatigue >= 82 || battery.readiness < 38
        ? "exhausted"
        : battery.fatigue >= 58 || battery.readiness < 62
          ? "strained"
          : "ready";
    }
  }
  state.campaign.missionInterceptionsAtStart = state.interceptions;
  state.campaign.missionImpactsAtStart = state.impacts;
  state.campaign.missionDepotProducedAtStart = state.campaign.depot.producedTotal;
  state.campaign.missionDepotLostAtStart = state.campaign.depot.lostTotal;
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

export function campaignDepotProductionRate(depot: CampaignAmmoDepot) {
  if (depot.repairRemainingMs > 0 || depot.health <= 0) return 0;
  return depot.health <= 50 ? 1 : 2;
}

export function advanceCampaignDepot(state: GameState, deltaMs: number, combatActive: boolean) {
  const campaign = state.campaign;
  if (!campaign || campaign.intermission || campaign.completed || state.status !== "active") return state;
  const depot = campaign.depot;
  const safeDelta = Math.max(0, deltaMs);
  if (depot.repairRemainingMs > 0) {
    if (combatActive) {
      depot.repairRemainingMs = Math.max(0, depot.repairRemainingMs - safeDelta);
      if (depot.repairRemainingMs === 0) {
        depot.health = 100;
        depot.stockLossApplied = false;
      }
    }
    return state;
  }
  const rate = campaignDepotProductionRate(depot);
  if (rate <= 0) return state;
  depot.productionProgressMs += safeDelta;
  while (depot.productionProgressMs >= CAMPAIGN_DEPOT_PRODUCTION_INTERVAL_MS) {
    depot.productionProgressMs -= CAMPAIGN_DEPOT_PRODUCTION_INTERVAL_MS;
    depot.stock += rate;
    depot.producedTotal += rate;
  }
  return state;
}

export function damageCampaignDepot(state: GameState, baseDamage: number) {
  const campaign = state.campaign;
  if (!campaign || baseDamage <= 0) return { damage: 0, stockLost: 0 };
  const depot = campaign.depot;
  const previousHealth = depot.health;
  const damage = Math.max(0, baseDamage * 1.25);
  depot.health = clamp(depot.health - damage, 0, 100);
  let stockLost = 0;
  if (previousHealth > 0 && depot.health <= 0 && !depot.stockLossApplied) {
    const retained = Math.floor(depot.stock / 2);
    stockLost = depot.stock - retained;
    depot.stock = retained;
    depot.lostTotal += stockLost;
    depot.stockLossApplied = true;
    depot.productionProgressMs = 0;
  }
  return { damage, stockLost };
}

export function serviceCampaignDepot(state: GameState) {
  const campaign = state.campaign;
  if (!campaign || campaign.intermission || campaign.completed || state.status !== "active") return state;
  const depot = campaign.depot;
  if (depot.health >= 100 || depot.repairRemainingMs > 0) {
    state.placementWarning = depot.repairRemainingMs > 0 ? "Ремонт складу вже триває" : "Склад БК не потребує ремонту";
    return state;
  }
  if (campaign.campaignWallet < CAMPAIGN_DEPOT_REPAIR_COST) {
    state.placementWarning = "Недостатньо коштів для ремонту складу БК";
    return state;
  }
  campaign.campaignWallet -= CAMPAIGN_DEPOT_REPAIR_COST;
  state.resources.budget = campaign.campaignWallet;
  depot.repairRemainingMs = CAMPAIGN_DEPOT_REPAIR_DURATION_MS;
  depot.productionProgressMs = 0;
  state.placementWarning = null;
  return state;
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
    outcome: "victory",
    missionIndex: campaign.missionIndex,
    missionId: mission.id,
    title: mission.title,
    durationSeconds: Math.max(0, Math.round((state.elapsedMs - state.cycleStartedAtMs) / 1_000)),
    totalTargets,
    interceptions,
    impacts,
    killReward: campaign.missionKillReward,
    bonusRewards,
    penaltyCosts,
    walletAfterMission: campaign.campaignWallet,
    civilianResilienceAfterMission: campaign.civilianResilience,
    minimumCityHp: Math.min(...state.cities.map((city) => city.infrastructure)),
    missionGrant: campaign.missionGrant,
    depotHealth: campaign.depot.health,
    depotStock: campaign.depot.stock,
    depotProduced: campaign.depot.producedTotal - campaign.missionDepotProducedAtStart,
    depotLost: campaign.depot.lostTotal - campaign.missionDepotLostAtStart,
    objectiveMet: objective.objectiveMet,
    objectiveSummary: objective.summary,
    rewardLines: lines,
  };
  campaign.previousMissionResults = [...campaign.previousMissionResults, result];
  campaign.lastAttemptResult = null;
  campaign.retryCheckpoint = null;
  campaign.intermission = true;
  campaign.completed = campaign.missionIndex >= 5;
  return result;
}

export function recordCampaignDefeat(state: GameState, failedCityId: CityId): CampaignMissionResult | null {
  const campaign = state.campaign;
  if (!campaign || campaign.lastAttemptResult?.outcome === "defeat") return campaign?.lastAttemptResult || null;
  const mission = getCampaignMission(campaign.missionIndex);
  const result: CampaignMissionResult = {
    outcome: "defeat",
    missionIndex: campaign.missionIndex,
    missionId: mission.id,
    title: mission.title,
    durationSeconds: Math.max(0, Math.round((state.elapsedMs - state.cycleStartedAtMs) / 1_000)),
    totalTargets: campaign.spawnEvents.length || missionTargetCount(mission),
    interceptions: state.interceptions - campaign.missionInterceptionsAtStart,
    impacts: state.impacts - campaign.missionImpactsAtStart,
    killReward: campaign.missionKillReward,
    bonusRewards: 0,
    penaltyCosts: 0,
    walletAfterMission: campaign.campaignWallet,
    civilianResilienceAfterMission: campaign.civilianResilience,
    minimumCityHp: Math.min(...state.cities.map((city) => city.infrastructure)),
    failedCityId,
    missionGrant: campaign.missionGrant,
    depotHealth: campaign.depot.health,
    depotStock: campaign.depot.stock,
    depotProduced: campaign.depot.producedTotal - campaign.missionDepotProducedAtStart,
    depotLost: campaign.depot.lostTotal - campaign.missionDepotLostAtStart,
    objectiveMet: false,
    objectiveSummary: `Місію програно: місто ${state.cities.find((city) => city.id === failedCityId)?.name || failedCityId} втратило всі міські служби.`,
    rewardLines: [
      { label: "Грант місії", amount: campaign.missionGrant, kind: "grant" },
      ...(campaign.missionKillReward ? [{ label: "Зароблено у невдалій спробі", amount: campaign.missionKillReward, kind: "kill" as const }] : []),
    ],
  };
  campaign.lastAttemptResult = result;
  return result;
}

export function captureCampaignAttemptCheckpoint(state: GameState, simulationRandomCursor: number) {
  if (!state.campaign) return state;
  const cloned = structuredClone(state);
  const campaign = cloned.campaign!;
  const { retryCheckpoint: _checkpoint, lastAttemptResult: _lastAttempt, ...campaignSnapshot } = campaign;
  const { campaign: _campaign, ...gameSnapshot } = cloned;
  state.campaign.retryCheckpoint = {
    game: gameSnapshot,
    campaign: campaignSnapshot,
    simulationRandomCursor,
  };
  state.campaign.lastAttemptResult = null;
  return state;
}

export function restoreCampaignAttempt(state: GameState) {
  const checkpoint = state.campaign?.retryCheckpoint;
  if (!checkpoint) return null;
  const restoredCheckpoint = structuredClone(checkpoint);
  const game: GameState = {
    ...restoredCheckpoint.game,
    campaign: {
      ...restoredCheckpoint.campaign,
      retryCheckpoint: restoredCheckpoint,
      lastAttemptResult: null,
    },
  };
  const authoredTargets = new Map(
    buildCampaignSpawnEvents(game.campaign!.missionIndex).map((event) => [event.id, event.targetAsset]),
  );
  game.campaign!.spawnEvents = game.campaign!.spawnEvents.map((event) => ({
    ...event,
    targetAsset: authoredTargets.get(event.id),
  }));
  game.status = "active";
  game.statusReason = "";
  game.cyclePhase = "planning";
  game.currentAttackPlan = null;
  game.campaignAttackSchedule = null;
  game.liveThreats = [];
  game.pendingLaunches = [];
  game.engagementEvents = [];
  game.impactMarkers = [];
  return { game, simulationRandomCursor: checkpoint.simulationRandomCursor };
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
  campaign.lastAttemptResult = null;
  campaign.retryCheckpoint = null;
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
    missionReserve: unit.missionReserveCapacity === "infinite" ? "infinite" : 0,
    manualOverrideTargets: [],
    assignedCityId: state.campaign.missionIndex === 2 ? "odesa" : "kyiv",
    health: 100,
    experienceLevel: 0,
    createdAtMission: state.campaign.missionIndex,
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
  const secondMissionReinforcementLeadMs = campaign.missionIndex === 2 && nextEvent.threatKind === "iskander" && nextEvent.routeId === "R27" ? 90_000 : 0;
  const desiredDueMs = phaseElapsedMs + Math.max(standardGapMs, ballisticLeadMs, cruiseLeadMs, firstMissionReinforcementLeadMs, secondMissionReinforcementLeadMs);
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

export function generateCampaignRoute(event: CampaignSpawnEvent, random: () => number, launchOrigin?: Coordinates, targetCoordinates?: Coordinates): Coordinates[] {
  const route = getCampaignRoute(event.routeId);
  if (!route) return [];
  const baseWaypoints = routeFromLaunchOrigin(route.baseWaypoints, launchOrigin);
  if (route.ballistic || event.threatKind === "iskander" || event.threatKind === "ballistic") {
    const start = copyPoint(baseWaypoints[0]);
    const end = copyPoint(baseWaypoints.at(-1)!);
    if (!launchOrigin) { start.lat += (random() - .5) * .08; start.lng += (random() - .5) * .08; }
    if (event.targetAsset === "ammo-depot" && targetCoordinates) {
      end.lat = targetCoordinates.lat;
      end.lng = targetCoordinates.lng;
    } else {
      end.lat += (random() - .5) * .025;
      end.lng += (random() - .5) * .025;
    }
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
  const generated = samplePolyline(chaikin(points), points.length);
  if (event.targetAsset === "ammo-depot" && targetCoordinates && generated.length) {
    generated[generated.length - 1] = copyPoint(targetCoordinates);
  }
  return generated;
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

export function serviceCampaignBattery(state: GameState, batteryId: string, action: "repair" | "resupply", _portion: .5 | 1 = .5): GameState {
  if (!state.campaign || !state.campaign.intermission) return state;
  const battery = [...state.batteries, ...state.storedBatteries].find((item) => item.id === batteryId);
  if (!battery) return state;
  if (action === "resupply") {
    state.placementWarning = "БК тепер автоматично надходить зі складу після циклу перезаряджання";
    return state;
  }
  const cost = campaignRepairCost(battery);
  if (cost <= 0 || state.campaign.campaignWallet < cost) return state;
  state.campaign.campaignWallet -= cost;
  state.resources.budget = state.campaign.campaignWallet;
  battery.health = 100;
  battery.readiness = Math.max(battery.readiness, 90);
  state.placementWarning = null;
  return state;
}
