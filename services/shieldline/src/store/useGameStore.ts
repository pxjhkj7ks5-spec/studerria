import { create } from "zustand";
import { persist } from "zustand/middleware";
import { initialCities } from "../data/mapData";
import { campaignTutorialComplete, campaignTutorialPlacementAction, recordCampaignTutorialAction as recordTutorialAction, settleCampaignTutorial } from "../data/campaignPlan";
import { defenseReadinessForMode, getGameModeRuntimePolicy } from "../data/gameModes";
import { threatTelemetryFor } from "../data/threatFlightProfiles";
import { getUnitDefinition } from "../data/units";
import { classificationTier, threatDisplayLabel } from "../game/airDefenseRules.mjs";
import { createDeterministicRandom } from "../game/deterministicRandom";
import { advanceSimulation, deployStoredBattery, moveBatteryToStorage as moveBatteryToStorageState, placeBattery, setBatteryManualOverride, startAttackNow } from "../game/liveSimulation";
import { createInitialState, createScenarioState } from "../game/initialState";
import { createLaunchSectorState, sectorSupportsThreat } from "../game/launchSystem.mjs";
import { togglePlanningAction } from "../game/planningActions";
import { advanceCampaignDepot, advanceCampaignMission as advanceCampaignMissionState, applyCampaignMissionOpening, captureCampaignAttemptCheckpoint, createCampaignAmmoDepot, createCampaignState, restoreCampaignAttempt, serviceCampaignBattery, serviceCampaignDepot, unlockedCampaignMissionIndex } from "../game/campaignMeta";
import type { CampaignAttackSchedule, CampaignMode, CampaignTutorialAction, Coordinates, GameState, LaunchAreaState, LaunchDirection, MapMode, PlanningActionId, ThreatKind, UnitKind } from "../types/game";
import type { GameModeId, OperationPhase, PersistentDailyCity, SimulationSpeed } from "../domain/contracts";

const tutorialKey = "shieldline-tutorial-complete-v1";

function readTutorialDismissed() {
  if (typeof window === "undefined") return false;
  return window.localStorage.getItem(tutorialKey) === "true";
}

function createSimulationSeed(mode: GameModeId | "legacy") {
  const suffix = typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.round(performance.now())}`;
  return `${mode}-${suffix}`;
}

function createSeededScenario(seed: string, mode: CampaignMode, scenarioId: string) {
  const random = createDeterministicRandom(seed);
  return { game: createScenarioState(() => random.next(), mode, scenarioId), cursor: random.cursor() };
}

function validCoordinates(value: unknown): value is Coordinates {
  const point = value as Partial<Coordinates> | null;
  return Boolean(point && Number.isFinite(point.lat) && Number.isFinite(point.lng));
}

const launchDirections: LaunchDirection[] = ["north", "east", "south"];

function normalizeCampaignSchedule(game: GameState): CampaignAttackSchedule | null {
  if (game.cyclePhase !== "attack" || game.scenarioId !== "thirty-days-under-pressure") return null;
  const persisted = game.campaignAttackSchedule;
  const directions = Array.isArray(persisted?.directions)
    ? persisted.directions.filter((direction): direction is LaunchDirection => launchDirections.includes(direction as LaunchDirection))
    : [];
  const uniqueDirections = [...new Set(directions)];
  for (const direction of launchDirections) if (!uniqueDirections.includes(direction)) uniqueDirections.push(direction);
  const phaseElapsed = Math.max(0, game.elapsedMs - game.cycleStartedAtMs);
  const inferredStage = Math.min(2, Math.floor(phaseElapsed / 60_000));
  return {
    profile: "guided-three-stage",
    directions: uniqueDirections.slice(0, 3),
    stageIndex: Number.isInteger(persisted?.stageIndex) ? Math.max(0, Math.min(2, persisted!.stageIndex)) : inferredStage,
    stageLaunchCount: Number.isInteger(persisted?.stageLaunchCount) ? Math.max(0, Math.min(3, persisted!.stageLaunchCount)) : 0,
    nextLaunchAtMs: Number.isFinite(persisted?.nextLaunchAtMs) ? persisted!.nextLaunchAtMs : game.elapsedMs + 1_000,
    ballisticLaunched: Boolean(persisted?.ballisticLaunched),
  };
}

function migratedTutorialStep(step: number, persistedVersion: number) {
  if (persistedVersion >= 23) return Math.max(0, Math.min(8, step));
  const version22Step = persistedVersion > 21
    ? Math.max(0, Math.min(5, step))
    : step <= 2 ? Math.max(0, step) : step >= 7 ? 5 : step >= 6 ? 4 : 3;
  return [0, 1, 3, 4, 7, 8][version22Step] ?? 8;
}

function recordPlacedTutorialAssets(game: GameState, nowMs: number) {
  if (!game.campaign || game.campaign.missionIndex !== 1) return false;
  let advanced = false;
  if (game.campaign.tutorialStep <= 3 && game.batteries.some((battery) => battery.id === "campaign-m1-long-radar" || battery.kind === "long-radar")) {
    advanced = recordTutorialAction(game.campaign, "place-long-radar-near-kyiv", nowMs) || advanced;
  }
  if (game.campaign.tutorialStep <= 4 && game.batteries.some((battery) => battery.id === "campaign-m1-mvg")) {
    advanced = recordTutorialAction(game.campaign, "place-mvg-east-of-kyiv", nowMs) || advanced;
  }
  const depot = game.campaign.depot;
  const paidDepotMvg = game.batteries.find((battery) => battery.kind === "mvg"
    && battery.id !== "campaign-m1-mvg"
    && Math.hypot(battery.position.lat - depot.position.lat, battery.position.lng - depot.position.lng) * 100 <= getUnitDefinition("mvg").primaryRangeKm);
  if (paidDepotMvg) {
    advanced = recordTutorialAction(game.campaign, "purchase-depot-mvg", nowMs) || advanced;
    advanced = recordTutorialAction(game.campaign, "place-mvg-near-depot", nowMs) || advanced;
  }
  return advanced;
}

export function normalizePersistedGame(game: GameState | null, persistedVersion = 23, campaignSeed = "campaign-migrated") {
  if (!game) return game;
  const persistedSectorById = new Map((Array.isArray(game.launchSectors) ? game.launchSectors : []).map((sector) => [sector.id, sector]));
  const launchSectors = createLaunchSectorState().map((sector) => {
    const persisted = persistedSectorById.get(sector.id);
    if (!persisted) return sector;
    const persistedState = persisted.state;
    const state: LaunchAreaState = persistedState === "warning" || persistedState === "launching" || persistedState === "cooldown" ? persistedState : "idle";
    return {
      ...sector,
      state,
      stateUntilMs: Number.isFinite(persisted.stateUntilMs) ? persisted.stateUntilMs : undefined,
      warningStartedAtMs: Number.isFinite(persisted.warningStartedAtMs) ? persisted.warningStartedAtMs : undefined,
      targetCityId: persisted.targetCityId,
      targetCoordinates: validCoordinates(persisted.targetCoordinates) ? { ...persisted.targetCoordinates } : undefined,
      targetHeadingDeg: Number.isFinite(persisted.targetHeadingDeg) ? persisted.targetHeadingDeg : undefined,
      lastLaunchCoordinates: validCoordinates(persisted.lastLaunchCoordinates) ? { ...persisted.lastLaunchCoordinates } : undefined,
      activeThreatKind: persisted.activeThreatKind && sectorSupportsThreat(sector, persisted.activeThreatKind) ? persisted.activeThreatKind : undefined,
    };
  });
  const authoritativeSectorById = new Map(launchSectors.map((sector) => [sector.id, sector]));
  const pendingLaunches = (Array.isArray(game.pendingLaunches) ? game.pendingLaunches : [])
    .filter((launch) => {
      const sector = authoritativeSectorById.get(launch.sectorId);
      return Boolean(sector && validCoordinates(launch.origin) && sectorSupportsThreat(sector, launch.kind));
    })
    .map((launch) => ({ ...launch, origin: { ...launch.origin } }));
  const engagementEvents = (Array.isArray(game.engagementEvents) ? game.engagementEvents : [])
    .filter((event) => event
      && validCoordinates(event.startPosition)
      && validCoordinates(event.targetStartPosition)
      && validCoordinates(event.targetPredictedPosition)
      && Number.isFinite(event.durationMs)
      && event.durationMs > 0
      && Number.isFinite(event.progress)
      && event.progress >= 0
      && event.progress < 1)
    .map((event) => ({
      ...event,
      startPosition: { ...event.startPosition },
      targetStartPosition: { ...event.targetStartPosition },
      targetPredictedPosition: { ...event.targetPredictedPosition },
    }));
  const engagedTargetIds = new Set(engagementEvents.filter((event) => event.style !== "radar" && !event.resolved).map((event) => event.targetId));
  const liveThreats = (Array.isArray(game.liveThreats) ? game.liveThreats : [])
    .filter((threat) => threat.id !== "opening-track-1"
      && validCoordinates(threat.origin)
      && validCoordinates(threat.target)
      && Number.isFinite(threat.progress)
      && threat.progress >= 0
      && threat.progress < 1
      && Number.isFinite(threat.speed)
      && threat.speed > 0)
    .map((threat) => ({
      ...threat,
      status: threat.status === "engaged" && !engagedTargetIds.has(threat.id) ? "inbound" as const : threat.status,
      ...(() => {
        const fallback = threatTelemetryFor(threat.kind, threat.id);
        return {
          speedKph: Number.isFinite(threat.speedKph) && threat.speedKph > 0 ? threat.speedKph : fallback.speedKph,
          altitudeM: Number.isFinite(threat.altitudeM) && threat.altitudeM > 0 ? threat.altitudeM : fallback.altitudeM,
        };
      })(),
      origin: { ...threat.origin },
      target: { ...threat.target },
      lastKnownPosition: validCoordinates(threat.lastKnownPosition) ? { ...threat.lastKnownPosition } : undefined,
      routeWaypoints: Array.isArray(threat.routeWaypoints) ? threat.routeWaypoints.filter(validCoordinates).map((point) => ({ ...point })) : undefined,
      classification: threat.classification || classificationTier(threat.confidence || 0),
      displayLabel: threat.displayLabel || threatDisplayLabel(threat.kind, threat.confidence || 0),
      fireControlQuality: Number.isFinite(threat.fireControlQuality) ? threat.fireControlQuality : 0,
      speedModifier: Number.isFinite(threat.speedModifier) ? threat.speedModifier : 1,
      damageModifier: Number.isFinite(threat.damageModifier) ? threat.damageModifier : 1,
    }));
  const normalizeBattery = (battery: GameState["batteries"][number]) => {
    const unit = getUnitDefinition(battery.kind);
    return {
      ...battery,
      position: { ...battery.position },
      health: Number.isFinite(battery.health) ? battery.health : battery.readiness,
      experienceLevel: Number.isFinite(battery.experienceLevel) ? battery.experienceLevel : 0,
      createdAtMission: Number.isFinite(battery.createdAtMission) ? battery.createdAtMission : 0,
      lastMovedMission: Number.isFinite(battery.lastMovedMission) ? battery.lastMovedMission : 0,
      missionReserve: game.campaign && unit.missionReserveCapacity !== "infinite" ? 0 : battery.missionReserve ?? unit.missionReserveCapacity,
      manualOverrideTargets: Array.isArray(battery.manualOverrideTargets) ? battery.manualOverrideTargets : [],
    };
  };
  type LegacyCampaignState = NonNullable<GameState["campaign"]> & { campaignAmmoStock?: number };
  const persistedCampaign = game.campaign as LegacyCampaignState | null;
  const campaignWithoutLegacyAmmo: Omit<LegacyCampaignState, "campaignAmmoStock"> | null = persistedCampaign
    ? (({ campaignAmmoStock: _legacyAmmoStock, ...campaign }) => campaign)(persistedCampaign)
    : null;
  const migratedDepot = createCampaignAmmoDepot(
    campaignSeed,
    Number.isFinite(persistedCampaign?.campaignAmmoStock) ? Number(persistedCampaign?.campaignAmmoStock) : 0,
  );
  const depot = persistedCampaign?.depot ? {
    ...migratedDepot,
    ...persistedCampaign.depot,
    position: validCoordinates(persistedCampaign.depot.position) ? { ...persistedCampaign.depot.position } : migratedDepot.position,
    health: Number.isFinite(persistedCampaign.depot.health) ? Math.max(0, Math.min(100, persistedCampaign.depot.health)) : 100,
    stock: Number.isFinite(persistedCampaign.depot.stock) ? Math.max(0, persistedCampaign.depot.stock) : migratedDepot.stock,
    productionProgressMs: Number.isFinite(persistedCampaign.depot.productionProgressMs) ? Math.max(0, persistedCampaign.depot.productionProgressMs) : 0,
    repairRemainingMs: Number.isFinite(persistedCampaign.depot.repairRemainingMs) ? Math.max(0, persistedCampaign.depot.repairRemainingMs) : 0,
    producedTotal: Number.isFinite(persistedCampaign.depot.producedTotal) ? Math.max(0, persistedCampaign.depot.producedTotal) : 0,
    lostTotal: Number.isFinite(persistedCampaign.depot.lostTotal) ? Math.max(0, persistedCampaign.depot.lostTotal) : 0,
    stockLossApplied: Boolean(persistedCampaign.depot.stockLossApplied),
  } : migratedDepot;
  const normalizedGame: GameState = {
    ...game,
    cities: game.cities.map((city) => ({
      ...city,
      alertUntilMs: Number.isFinite(city.alertUntilMs) ? Math.max(0, Number(city.alertUntilMs)) : 0,
    })),
    campaignAttackSchedule: normalizeCampaignSchedule(game),
    launchSectors,
    pendingLaunches,
    carriers: Array.isArray(game.carriers) ? game.carriers : [],
    batteries: (Array.isArray(game.batteries) ? game.batteries : []).map(normalizeBattery),
    storedBatteries: (Array.isArray(game.storedBatteries) ? game.storedBatteries : []).map(normalizeBattery),
    liveThreats,
    engagementEvents,
    softKills: Number.isFinite(game.softKills) ? game.softKills : 0,
    campaign: persistedCampaign ? {
      ...campaignWithoutLegacyAmmo!,
      depot,
      lastAttemptResult: persistedCampaign.lastAttemptResult || null,
      retryCheckpoint: persistedCampaign.retryCheckpoint || null,
      missionDepotProducedAtStart: Number.isFinite(persistedCampaign.missionDepotProducedAtStart) ? persistedCampaign.missionDepotProducedAtStart : depot.producedTotal,
      missionDepotLostAtStart: Number.isFinite(persistedCampaign.missionDepotLostAtStart) ? persistedCampaign.missionDepotLostAtStart : depot.lostTotal,
      tutorialStep: migratedTutorialStep(Number.isInteger(persistedCampaign.tutorialStep) ? persistedCampaign.tutorialStep : 0, persistedVersion),
      tutorialActionQueue: Array.isArray(persistedCampaign.tutorialActionQueue) ? persistedCampaign.tutorialActionQueue : [],
      tutorialNextPromptAtMs: Number.isFinite(persistedCampaign.tutorialNextPromptAtMs) ? persistedCampaign.tutorialNextPromptAtMs : 0,
    } : null,
  };
  applyCampaignMissionOpening(normalizedGame);
  recordPlacedTutorialAssets(normalizedGame, Date.now());
  return normalizedGame;
}

export function campaignCycleCompleted(previous: GameState, next: GameState) {
  return previous.cyclePhase === "attack"
    && next.cyclePhase === "planning"
    && next.afterActionReports.length > previous.afterActionReports.length;
}

export interface GameStore {
  game: GameState;
  campaignMode: CampaignMode | null;
  activeGameMode: GameModeId | null;
  dailyCityGame: GameState | null;
  pendingCampaignMode: CampaignMode | null;
  mapMode: MapMode;
  tutorialDismissed: boolean;
  placementKind: UnitKind | null;
  placementStoredBatteryId: string | null;
  operationPhase: OperationPhase;
  countdownRemainingMs: number;
  simulationSpeed: SimulationSpeed;
  simulationSeed: string;
  simulationRandomCursor: number;
  selectCampaignMode: (mode: CampaignMode) => void;
  launchTacticalMode: (mode: GameModeId) => void;
  openCampaignMission: (missionIndex: number) => void;
  hydrateDailyCity: (city: PersistentDailyCity) => void;
  selectScenario: (scenarioId: string) => void;
  clearScenarioSelection: () => void;
  returnToModeSelect: () => void;
  setMapMode: (mode: MapMode) => void;
  dismissTutorial: () => void;
  recordCampaignTutorialAction: (action: CampaignTutorialAction, nowMs?: number) => void;
  refreshCampaignTutorial: (nowMs?: number) => void;
  beginPlacement: (kind: UnitKind) => void;
  cancelPlacement: () => void;
  placeSelectedBattery: (position: Coordinates) => void;
  moveBatteryToStorage: (batteryId: string) => void;
  setBatteryManualOverride: (batteryId: string, threatKind: ThreatKind, enabled: boolean) => void;
  togglePlanningAction: (actionId: PlanningActionId) => void;
  startOperation: () => void;
  pauseOperation: () => void;
  resumeOperation: () => void;
  triggerNextWave: () => void;
  advanceOperation: (deltaMs: number) => void;
  resetCampaign: () => void;
  retryCampaignMission: () => void;
  advanceCampaignMission: () => void;
  serviceCampaignBattery: (batteryId: string, action: "repair" | "resupply", portion?: .5 | 1) => void;
  serviceCampaignDepot: () => void;
}

const initialSeed = createSimulationSeed("legacy");
const initialRandom = createDeterministicRandom(initialSeed);

export const useGameStore = create<GameStore>()(
  persist(
    (set, get) => ({
      game: createInitialState(() => initialRandom.next()),
      campaignMode: null,
      activeGameMode: null,
      dailyCityGame: null,
      pendingCampaignMode: null,
      mapMode: "live",
      tutorialDismissed: readTutorialDismissed(),
      placementKind: null,
      placementStoredBatteryId: null,
      operationPhase: "planning",
      countdownRemainingMs: 0,
      simulationSpeed: 1,
      simulationSeed: initialSeed,
      simulationRandomCursor: initialRandom.cursor(),
      selectCampaignMode: (mode) => set({
        pendingCampaignMode: mode,
      }),
      launchTacticalMode: (mode) => {
        const policy = getGameModeRuntimePolicy(mode);
        const seed = createSimulationSeed(mode);
        if (mode === "daily-defense") {
          const dailyGame = get().dailyCityGame || createScenarioState(Math.random, "crisis", "thirty-days-under-pressure");
          set({ campaignMode: "crisis", activeGameMode: mode, pendingCampaignMode: null, mapMode: "live", game: dailyGame, placementKind: null, placementStoredBatteryId: null, operationPhase: "planning", countdownRemainingMs: 0, simulationSpeed: policy.defaultSpeed, simulationSeed: seed, simulationRandomCursor: 0 });
          return;
        }
        const profile = {
          campaign: { campaignMode: "crisis" as const, scenarioId: "thirty-days-under-pressure" },
          "rapid-response": { campaignMode: "seven-day" as const, scenarioId: "grid-pressure" },
          "ranked-challenge": { campaignMode: "crisis" as const, scenarioId: "grid-pressure" },
          "co-op-command": { campaignMode: "crisis" as const, scenarioId: "thirty-days-under-pressure" },
          sandbox: { campaignMode: "sandbox" as const, scenarioId: "decoy-storm" },
          training: { campaignMode: "training" as const, scenarioId: "first-night" },
        }[mode];
        const seeded = createSeededScenario(seed, profile.campaignMode, profile.scenarioId);
        if (mode === "campaign") {
          seeded.game.campaign = createCampaignState(1, 0, seed);
          seeded.game.cities = seeded.game.cities.map((city) => ({ ...city, infrastructure: 100, damage: 0 }));
          seeded.game.resources.budget = 0;
          applyCampaignMissionOpening(seeded.game);
        }
        set({
          campaignMode: profile.campaignMode,
          activeGameMode: mode,
          pendingCampaignMode: null,
          mapMode: "live",
          game: seeded.game,
          placementKind: null,
          placementStoredBatteryId: null,
          operationPhase: "planning",
          countdownRemainingMs: 0,
          simulationSpeed: policy.defaultSpeed,
          simulationSeed: seed,
          simulationRandomCursor: seeded.cursor,
        });
      },
      openCampaignMission: (missionIndex) => {
        const current = get();
        if (!current.game.campaign) {
          if (missionIndex === 1) current.launchTacticalMode("campaign");
          return;
        }
        if (missionIndex < 1 || missionIndex > unlockedCampaignMissionIndex(current.game.campaign)) return;
        const game = structuredClone(current.game);
        if (game.campaign?.intermission && !game.campaign.completed && missionIndex === game.campaign.missionIndex + 1) {
          advanceCampaignMissionState(game);
        }
        if (!game.campaign || game.campaign.missionIndex !== missionIndex || game.campaign.intermission) return;
        const readiness = defenseReadinessForMode("campaign", game.batteries.map((battery) => battery.kind));
        const keepPhase = current.activeGameMode === "campaign" && current.game.campaign?.missionIndex === missionIndex;
        set({
          campaignMode: "crisis",
          activeGameMode: "campaign",
          pendingCampaignMode: null,
          mapMode: "live",
          game,
          placementKind: null,
          placementStoredBatteryId: null,
          operationPhase: keepPhase ? current.operationPhase : readiness.ready && (missionIndex !== 1 || campaignTutorialComplete(game.campaign)) ? "countdown" : "planning",
          countdownRemainingMs: keepPhase ? current.countdownRemainingMs : readiness.ready && (missionIndex !== 1 || campaignTutorialComplete(game.campaign)) ? getGameModeRuntimePolicy("campaign").countdownMs : 0,
        });
      },
      hydrateDailyCity: (city) => {
        let game = createScenarioState(() => 0.5, "crisis", "thirty-days-under-pressure");
        game = { ...game, resources: { ...game.resources, budget: 999 } };
        city.assets.forEach((asset, index) => {
          const fallback = initialCities.find((entry) => entry.id === asset.cityId)?.coordinates || initialCities[0].coordinates;
          const next = placeBattery(game, asset.kind as UnitKind, asset.position || fallback, () => (index + 1) / 100);
          const lastBattery = next.batteries.at(-1);
          game = lastBattery ? { ...next, batteries: next.batteries.map((battery) => battery.id === lastBattery.id ? { ...battery, readiness: asset.readiness, assignedCityId: asset.cityId as typeof battery.assignedCityId } : battery) } : next;
        });
        game = {
          ...game,
          resources: { ...game.resources, morale: city.morale, energy: city.energy },
          cities: game.cities.map((entry) => entry.id === "kyiv" ? { ...entry, infrastructure: city.infrastructure, damage: city.damage, morale: city.morale, energy: city.energy } : entry),
        };
        set({ campaignMode: "crisis", activeGameMode: "daily-defense", pendingCampaignMode: null, mapMode: "live", game, dailyCityGame: game, placementKind: null, placementStoredBatteryId: null, operationPhase: "planning", countdownRemainingMs: 0, simulationSpeed: 1 });
      },
      selectScenario: (scenarioId) => {
        const mode = get().pendingCampaignMode || "crisis";
        const seed = createSimulationSeed("legacy");
        const seeded = createSeededScenario(seed, mode, scenarioId);
        set({
          campaignMode: mode,
          pendingCampaignMode: null,
          mapMode: "live",
          game: seeded.game,
          placementKind: null,
          placementStoredBatteryId: null,
          operationPhase: "planning",
          countdownRemainingMs: 0,
          simulationSeed: seed,
          simulationRandomCursor: seeded.cursor,
        });
      },
      clearScenarioSelection: () => set({ pendingCampaignMode: null }),
      returnToModeSelect: () => set({ campaignMode: null, activeGameMode: null, pendingCampaignMode: null, placementKind: null, placementStoredBatteryId: null, operationPhase: "planning", countdownRemainingMs: 0 }),
      setMapMode: (mode) => set({ mapMode: mode }),
      dismissTutorial: () => {
        if (typeof window !== "undefined") {
          window.localStorage.setItem(tutorialKey, "true");
        }
        set({ tutorialDismissed: true });
      },
      recordCampaignTutorialAction: (action, nowMs = Date.now()) => set((state) => {
        if (!state.game.campaign || state.game.campaign.missionIndex !== 1 || state.operationPhase !== "planning") return state;
        const game = structuredClone(state.game);
        recordTutorialAction(game.campaign, action, nowMs);
        const readiness = defenseReadinessForMode("campaign", game.batteries.map((battery) => battery.kind));
        const tutorialReady = campaignTutorialComplete(game.campaign);
        return {
          ...state,
          game,
          operationPhase: tutorialReady && readiness.ready ? "countdown" : state.operationPhase,
          countdownRemainingMs: tutorialReady && readiness.ready ? getGameModeRuntimePolicy("campaign").countdownMs : state.countdownRemainingMs,
        };
      }),
      refreshCampaignTutorial: (nowMs = Date.now()) => set((state) => {
        if (!state.game.campaign || state.game.campaign.missionIndex !== 1 || state.operationPhase !== "planning") return state;
        const game = structuredClone(state.game);
        const reconciled = recordPlacedTutorialAssets(game, nowMs);
        const advanced = settleCampaignTutorial(game.campaign!, nowMs) || reconciled;
        if (!advanced) return state;
        const readiness = defenseReadinessForMode("campaign", game.batteries.map((battery) => battery.kind));
        const tutorialReady = campaignTutorialComplete(game.campaign);
        return {
          ...state,
          game,
          operationPhase: tutorialReady && readiness.ready ? "countdown" : state.operationPhase,
          countdownRemainingMs: tutorialReady && readiness.ready ? getGameModeRuntimePolicy("campaign").countdownMs : state.countdownRemainingMs,
        };
      }),
      beginPlacement: (kind) => set((state) => ({
        placementKind: kind,
        placementStoredBatteryId: state.game.storedBatteries?.find((battery) => battery.kind === kind)?.id || null,
      })),
      cancelPlacement: () => set({ placementKind: null, placementStoredBatteryId: null }),
      placeSelectedBattery: (position) => {
        const { game, placementKind, placementStoredBatteryId, simulationSeed, simulationRandomCursor, activeGameMode, operationPhase } = get();
        if (!placementKind) return;
        const random = createDeterministicRandom(simulationSeed, simulationRandomCursor);
        const nextGame = placementStoredBatteryId
          ? deployStoredBattery(game, placementStoredBatteryId, position)
          : placeBattery(game, placementKind, position, () => random.next());
        const placedBattery = nextGame.batteries.find((battery) => !game.batteries.some((current) => current.id === battery.id));
        if (placedBattery) {
          const tutorialAction = campaignTutorialPlacementAction(placedBattery.kind);
          if (tutorialAction && (placedBattery.kind !== "mvg" || placementStoredBatteryId === "campaign-m1-mvg")) {
            recordTutorialAction(nextGame.campaign, tutorialAction, Date.now());
          }
          if (placedBattery.kind === "mvg" && !placementStoredBatteryId && nextGame.campaign?.missionIndex === 1) {
            recordTutorialAction(nextGame.campaign, "purchase-depot-mvg", Date.now());
            const depot = nextGame.campaign.depot;
            const distanceKm = Math.hypot(position.lat - depot.position.lat, position.lng - depot.position.lng) * 100;
            if (distanceKm <= getUnitDefinition("mvg").primaryRangeKm) {
              recordTutorialAction(nextGame.campaign, "place-mvg-near-depot", Date.now());
            }
          }
        }
        const mode = activeGameMode || "training";
        const policy = getGameModeRuntimePolicy(mode);
        const readiness = defenseReadinessForMode(mode, nextGame.batteries.map((battery) => battery.kind));
        const tutorialAllowsStart = mode !== "campaign" || nextGame.campaign?.missionIndex !== 1 || campaignTutorialComplete(nextGame.campaign);
        const shouldAutoStart = policy.start === "auto-checklist" && readiness.ready && tutorialAllowsStart && operationPhase === "planning";
        set({ game: nextGame, dailyCityGame: mode === "daily-defense" ? nextGame : get().dailyCityGame, placementKind: nextGame.placementWarning ? placementKind : null, placementStoredBatteryId: nextGame.placementWarning ? placementStoredBatteryId : null, simulationRandomCursor: placementStoredBatteryId ? simulationRandomCursor : random.cursor(), operationPhase: shouldAutoStart ? "countdown" : operationPhase, countdownRemainingMs: shouldAutoStart ? policy.countdownMs : get().countdownRemainingMs });
      },
      moveBatteryToStorage: (batteryId) => set((state) => {
        const game = moveBatteryToStorageState(state.game, batteryId);
        return {
          game,
          dailyCityGame: state.activeGameMode === "daily-defense" ? game : state.dailyCityGame,
          placementKind: null,
          placementStoredBatteryId: null,
        };
      }),
      setBatteryManualOverride: (batteryId, threatKind, enabled) => set((state) => {
        const game = setBatteryManualOverride(state.game, batteryId, threatKind, enabled);
        return { game, dailyCityGame: state.activeGameMode === "daily-defense" ? game : state.dailyCityGame };
      }),
      togglePlanningAction: (actionId) => set((state) => { const game = togglePlanningAction(state.game, actionId); return { game, dailyCityGame: state.activeGameMode === "daily-defense" ? game : state.dailyCityGame }; }),
      startOperation: () => set((state) => {
        const mode = state.activeGameMode || "training";
        const policy = getGameModeRuntimePolicy(mode);
        if (policy.execution !== "live" || state.operationPhase !== "planning") return state;
        if (mode === "campaign" && state.game.campaign?.missionIndex === 1 && !campaignTutorialComplete(state.game.campaign)) return state;
        const readiness = defenseReadinessForMode(mode, state.game.batteries.map((battery) => battery.kind));
        if (!readiness.ready) return { ...state, game: { ...state.game, placementWarning: readiness.message } };
        if (policy.countdownMs > 0) return { ...state, game: { ...state.game, placementWarning: null }, operationPhase: "countdown", countdownRemainingMs: policy.countdownMs };
        const random = createDeterministicRandom(state.simulationSeed, state.simulationRandomCursor);
        const checkpointed = structuredClone({ ...state.game, placementWarning: null });
        if (mode === "campaign") captureCampaignAttemptCheckpoint(checkpointed, state.simulationRandomCursor);
        return { ...state, game: startAttackNow(checkpointed, () => random.next()), operationPhase: "running", countdownRemainingMs: 0, simulationRandomCursor: random.cursor() };
      }),
      pauseOperation: () => set((state) => state.operationPhase === "running" ? { operationPhase: "paused" } : state),
      resumeOperation: () => set((state) => state.operationPhase === "paused" ? { operationPhase: "running" } : state),
      triggerNextWave: () => set((state) => {
        if (state.activeGameMode !== "sandbox" || state.game.cyclePhase === "attack") return state;
        const random = createDeterministicRandom(state.simulationSeed, state.simulationRandomCursor);
        return { ...state, game: startAttackNow(state.game, () => random.next()), operationPhase: "running", simulationRandomCursor: random.cursor() };
      }),
      advanceOperation: (deltaMs) => {
        try {
          set((state) => {
            const mode = state.activeGameMode || "training";
            const policy = getGameModeRuntimePolicy(mode);
            if (policy.execution !== "live") return state;
            const random = createDeterministicRandom(state.simulationSeed, state.simulationRandomCursor);
            const depotClockActive = mode === "campaign" && state.operationPhase !== "completed";
            const depotGame = depotClockActive ? structuredClone(state.game) : state.game;
            if (depotClockActive) advanceCampaignDepot(depotGame, deltaMs, state.operationPhase === "running");
            if (state.operationPhase === "countdown") {
              const remaining = state.countdownRemainingMs - deltaMs;
              if (remaining > 0) return { game: depotGame, countdownRemainingMs: remaining };
              if (mode === "campaign") captureCampaignAttemptCheckpoint(depotGame, state.simulationRandomCursor);
              let game = startAttackNow(depotGame, () => random.next());
              const overflowMs = Math.max(0, -remaining) * state.simulationSpeed;
              if (overflowMs > 0) game = advanceSimulation(game, overflowMs, () => random.next());
              const campaignCompleted = mode === "campaign" && campaignCycleCompleted(state.game, game);
              return { game, operationPhase: campaignCompleted || game.status !== "active" ? "completed" : "running", countdownRemainingMs: 0, simulationRandomCursor: random.cursor() };
            }
            if (state.operationPhase !== "running") return depotClockActive ? { game: depotGame } : state;
            const game = advanceSimulation(depotGame, deltaMs * state.simulationSpeed, () => random.next());
            const campaignCompleted = mode === "campaign" && campaignCycleCompleted(state.game, game);
            return { game, operationPhase: campaignCompleted || game.status !== "active" ? "completed" : "running", simulationRandomCursor: random.cursor() };
          });
        } catch (error) {
          console.error("Shieldline simulation tick recovered", error);
          set((state) => ({ game: normalizePersistedGame(state.game) || state.game }));
        }
      },
      resetCampaign: () => {
        const mode = get().activeGameMode || "training";
        const seed = createSimulationSeed(mode);
        const seeded = createSeededScenario(seed, get().campaignMode || "crisis", get().game.scenarioId);
        if (mode === "campaign") {
          seeded.game.campaign = createCampaignState(1, 0, seed);
          seeded.game.cities = seeded.game.cities.map((city) => ({ ...city, infrastructure: 100, damage: 0 }));
          seeded.game.resources.budget = 0;
          applyCampaignMissionOpening(seeded.game);
        }
        set({ game: seeded.game, dailyCityGame: mode === "daily-defense" ? seeded.game : get().dailyCityGame, placementKind: null, placementStoredBatteryId: null, operationPhase: "planning", countdownRemainingMs: 0, simulationSpeed: getGameModeRuntimePolicy(mode).defaultSpeed, simulationSeed: seed, simulationRandomCursor: seeded.cursor });
      },
      retryCampaignMission: () => set((state) => {
        if (state.activeGameMode !== "campaign") return state;
        const restored = restoreCampaignAttempt(state.game);
        if (!restored) return state;
        return {
          ...state,
          game: restored.game,
          operationPhase: "planning",
          countdownRemainingMs: 0,
          placementKind: null,
          placementStoredBatteryId: null,
          simulationRandomCursor: restored.simulationRandomCursor,
        };
      }),
      advanceCampaignMission: () => set((state) => {
        if (state.activeGameMode !== "campaign") return state;
        const game = advanceCampaignMissionState(structuredClone(state.game));
        const readiness = defenseReadinessForMode("campaign", game.batteries.map((battery) => battery.kind));
        return { ...state, game, operationPhase: readiness.ready ? "countdown" : "planning", countdownRemainingMs: readiness.ready ? getGameModeRuntimePolicy("campaign").countdownMs : 0, placementKind: null, placementStoredBatteryId: null };
      }),
      serviceCampaignBattery: (batteryId, action, portion = .5) => set((state) => ({ ...state, game: serviceCampaignBattery(structuredClone(state.game), batteryId, action, portion) })),
      serviceCampaignDepot: () => set((state) => ({ ...state, game: serviceCampaignDepot(structuredClone(state.game)) })),
    }),
    {
      name: "shieldline-live-v7",
      version: 24,
      migrate: (persistedState, persistedVersion) => {
        const { selectedBatteryId: _discardedSelection, ...state } = persistedState as Partial<GameStore> & { selectedBatteryId?: string | null };
        const migratedGame = normalizePersistedGame(state.game || null, persistedVersion, state.simulationSeed || "campaign-migrated");
        return {
          ...state,
          ...(migratedGame ? { game: migratedGame } : {}),
          activeGameMode: state.activeGameMode === "campaign" && !migratedGame?.campaign ? null : state.activeGameMode,
          dailyCityGame: normalizePersistedGame(state.dailyCityGame || null, persistedVersion, state.simulationSeed || "daily-migrated"),
          simulationSpeed: 1,
        } as GameStore;
      },
      partialize: (state) => ({
        game: state.game,
        campaignMode: state.campaignMode,
        activeGameMode: state.activeGameMode,
        dailyCityGame: state.dailyCityGame,
        pendingCampaignMode: state.pendingCampaignMode,
        mapMode: state.mapMode,
        operationPhase: state.operationPhase,
        countdownRemainingMs: state.countdownRemainingMs,
        simulationSpeed: state.simulationSpeed,
        simulationSeed: state.simulationSeed,
        simulationRandomCursor: state.simulationRandomCursor,
      }),
    },
  ),
);

export type AccountProgressState = Pick<GameStore,
  | "game"
  | "campaignMode"
  | "activeGameMode"
  | "dailyCityGame"
  | "pendingCampaignMode"
  | "mapMode"
  | "operationPhase"
  | "countdownRemainingMs"
  | "simulationSpeed"
  | "simulationSeed"
  | "simulationRandomCursor"
>;

export function readAccountProgressState(): AccountProgressState {
  const state = useGameStore.getState();
  return {
    game: state.game,
    campaignMode: state.campaignMode,
    activeGameMode: state.activeGameMode,
    dailyCityGame: state.dailyCityGame,
    pendingCampaignMode: state.pendingCampaignMode,
    mapMode: state.mapMode,
    operationPhase: state.operationPhase,
    countdownRemainingMs: state.countdownRemainingMs,
    simulationSpeed: state.simulationSpeed,
    simulationSeed: state.simulationSeed,
    simulationRandomCursor: state.simulationRandomCursor,
  };
}

export function applyAccountProgressState(value: AccountProgressState) {
  const game = normalizePersistedGame(value?.game || null);
  if (!game || (value.activeGameMode === "campaign" && !game.campaign)) return false;
  useGameStore.setState({
    game,
    campaignMode: value.campaignMode || null,
    activeGameMode: value.activeGameMode || null,
    dailyCityGame: normalizePersistedGame(value.dailyCityGame || null),
    pendingCampaignMode: value.pendingCampaignMode || null,
    mapMode: value.mapMode || "live",
    operationPhase: value.operationPhase || "planning",
    countdownRemainingMs: Math.max(0, Number(value.countdownRemainingMs) || 0),
    simulationSpeed: 1,
    simulationSeed: String(value.simulationSeed || createSimulationSeed("legacy")),
    simulationRandomCursor: Math.max(0, Number(value.simulationRandomCursor) || 0),
    placementKind: null,
    placementStoredBatteryId: null,
  });
  return true;
}
