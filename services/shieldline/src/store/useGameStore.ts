import { create } from "zustand";
import { persist } from "zustand/middleware";
import { initialCities } from "../data/mapData";
import { defenseReadinessForMode, getGameModeRuntimePolicy } from "../data/gameModes";
import { createDeterministicRandom } from "../game/deterministicRandom";
import { advanceSimulation, deployStoredBattery, moveBatteryToStorage as moveBatteryToStorageState, placeBattery, startAttackNow } from "../game/liveSimulation";
import { createInitialState, createScenarioState } from "../game/initialState";
import { createLaunchSectorState, sectorSupportsThreat } from "../game/launchSystem.mjs";
import { togglePlanningAction } from "../game/planningActions";
import type { CampaignMode, Coordinates, GameState, LaunchAreaState, MapMode, PlanningActionId, UnitKind } from "../types/game";
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

export function normalizePersistedGame(game: GameState | null) {
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
    };
  });
  const authoritativeSectorById = new Map(launchSectors.map((sector) => [sector.id, sector]));
  const pendingLaunches = (Array.isArray(game.pendingLaunches) ? game.pendingLaunches : [])
    .filter((launch) => {
      const sector = authoritativeSectorById.get(launch.sectorId);
      return Boolean(sector && validCoordinates(launch.origin) && sectorSupportsThreat(sector, launch.kind));
    })
    .map((launch) => ({ ...launch, origin: { ...launch.origin } }));
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
      origin: { ...threat.origin },
      target: { ...threat.target },
      lastKnownPosition: validCoordinates(threat.lastKnownPosition) ? { ...threat.lastKnownPosition } : undefined,
    }));
  return {
    ...game,
    launchSectors,
    pendingLaunches,
    carriers: Array.isArray(game.carriers) ? game.carriers : [],
    storedBatteries: (Array.isArray(game.storedBatteries) ? game.storedBatteries : []).map((battery) => ({ ...battery, position: { ...battery.position } })),
    liveThreats,
  };
}

export function campaignCycleCompleted(previous: GameState, next: GameState) {
  return previous.cyclePhase === "attack"
    && next.cyclePhase === "planning"
    && next.afterActionReports.length > previous.afterActionReports.length;
}

interface GameStore {
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
  hydrateDailyCity: (city: PersistentDailyCity) => void;
  selectScenario: (scenarioId: string) => void;
  clearScenarioSelection: () => void;
  returnToModeSelect: () => void;
  setMapMode: (mode: MapMode) => void;
  dismissTutorial: () => void;
  beginPlacement: (kind: UnitKind) => void;
  cancelPlacement: () => void;
  placeSelectedBattery: (position: Coordinates) => void;
  moveBatteryToStorage: (batteryId: string) => void;
  togglePlanningAction: (actionId: PlanningActionId) => void;
  startOperation: () => void;
  pauseOperation: () => void;
  resumeOperation: () => void;
  triggerNextWave: () => void;
  advanceOperation: (deltaMs: number) => void;
  resetCampaign: () => void;
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
        const mode = activeGameMode || "training";
        const policy = getGameModeRuntimePolicy(mode);
        const readiness = defenseReadinessForMode(mode, nextGame.batteries.map((battery) => battery.kind));
        const shouldAutoStart = policy.start === "auto-checklist" && readiness.ready && operationPhase === "planning";
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
      togglePlanningAction: (actionId) => set((state) => { const game = togglePlanningAction(state.game, actionId); return { game, dailyCityGame: state.activeGameMode === "daily-defense" ? game : state.dailyCityGame }; }),
      startOperation: () => set((state) => {
        const mode = state.activeGameMode || "training";
        const policy = getGameModeRuntimePolicy(mode);
        if (policy.execution !== "live" || state.operationPhase !== "planning") return state;
        const readiness = defenseReadinessForMode(mode, state.game.batteries.map((battery) => battery.kind));
        if (!readiness.ready) return { ...state, game: { ...state.game, placementWarning: readiness.message } };
        if (policy.countdownMs > 0) return { ...state, game: { ...state.game, placementWarning: null }, operationPhase: "countdown", countdownRemainingMs: policy.countdownMs };
        const random = createDeterministicRandom(state.simulationSeed, state.simulationRandomCursor);
        return { ...state, game: startAttackNow({ ...state.game, placementWarning: null }, () => random.next()), operationPhase: "running", countdownRemainingMs: 0, simulationRandomCursor: random.cursor() };
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
            if (state.operationPhase === "countdown") {
              const remaining = state.countdownRemainingMs - deltaMs;
              if (remaining > 0) return { countdownRemainingMs: remaining };
              let game = startAttackNow(state.game, () => random.next());
              const overflowMs = Math.max(0, -remaining) * state.simulationSpeed;
              if (overflowMs > 0) game = advanceSimulation(game, overflowMs, () => random.next());
              const campaignCompleted = mode === "campaign" && campaignCycleCompleted(state.game, game);
              return { game, operationPhase: campaignCompleted || game.status !== "active" ? "completed" : "running", countdownRemainingMs: 0, simulationRandomCursor: random.cursor() };
            }
            if (state.operationPhase !== "running") return state;
            const game = advanceSimulation(state.game, deltaMs * state.simulationSpeed, () => random.next());
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
        set({ game: seeded.game, dailyCityGame: mode === "daily-defense" ? seeded.game : get().dailyCityGame, placementKind: null, placementStoredBatteryId: null, operationPhase: "planning", countdownRemainingMs: 0, simulationSpeed: getGameModeRuntimePolicy(mode).defaultSpeed, simulationSeed: seed, simulationRandomCursor: seeded.cursor });
      },
    }),
    {
      name: "shieldline-live-v7",
      version: 15,
      migrate: (persistedState) => {
        const { selectedBatteryId: _discardedSelection, ...state } = persistedState as Partial<GameStore> & { selectedBatteryId?: string | null };
        return {
          ...state,
          game: normalizePersistedGame(state.game || null) || undefined,
          dailyCityGame: normalizePersistedGame(state.dailyCityGame || null),
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
