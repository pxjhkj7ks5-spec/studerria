import { create } from "zustand";
import { persist } from "zustand/middleware";
import { placeBattery, removeBattery, setBatteryMaintenance, tickSimulation } from "../game/liveSimulation";
import { createInitialState, createScenarioState } from "../game/initialState";
import { togglePlanningAction } from "../game/planningActions";
import type { CampaignMode, Coordinates, GameState, MapMode, PlanningActionId, UnitKind } from "../types/game";
import type { GameModeId } from "../domain/contracts";

const tutorialKey = "shieldline-tutorial-complete-v1";

function readTutorialDismissed() {
  if (typeof window === "undefined") return false;
  return window.localStorage.getItem(tutorialKey) === "true";
}

interface GameStore {
  game: GameState;
  campaignMode: CampaignMode | null;
  activeGameMode: GameModeId | null;
  dailyCityGame: GameState | null;
  pendingCampaignMode: CampaignMode | null;
  mapMode: MapMode;
  tutorialDismissed: boolean;
  selectedBatteryId: string | null;
  placementKind: UnitKind | null;
  selectCampaignMode: (mode: CampaignMode) => void;
  launchTacticalMode: (mode: GameModeId) => void;
  selectScenario: (scenarioId: string) => void;
  clearScenarioSelection: () => void;
  returnToModeSelect: () => void;
  setMapMode: (mode: MapMode) => void;
  dismissTutorial: () => void;
  setSelectedBattery: (batteryId: string | null) => void;
  beginPlacement: (kind: UnitKind) => void;
  cancelPlacement: () => void;
  placeSelectedBattery: (position: Coordinates) => void;
  removeSelectedBattery: () => void;
  startSelectedBatteryMaintenance: () => void;
  togglePlanningAction: (actionId: PlanningActionId) => void;
  tick: (deltaMs: number) => void;
  resetCampaign: () => void;
}

export const useGameStore = create<GameStore>()(
  persist(
    (set, get) => ({
      game: createInitialState(),
      campaignMode: null,
      activeGameMode: null,
      dailyCityGame: null,
      pendingCampaignMode: null,
      mapMode: "live",
      tutorialDismissed: readTutorialDismissed(),
      selectedBatteryId: null,
      placementKind: null,
      selectCampaignMode: (mode) => set({
        pendingCampaignMode: mode,
      }),
      launchTacticalMode: (mode) => {
        if (mode === "daily-defense") {
          const dailyGame = get().dailyCityGame || createScenarioState(Math.random, "crisis", "thirty-days-under-pressure");
          set({ campaignMode: "crisis", activeGameMode: mode, pendingCampaignMode: null, mapMode: "live", game: dailyGame, selectedBatteryId: null, placementKind: null });
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
        set({
          campaignMode: profile.campaignMode,
          activeGameMode: mode,
          pendingCampaignMode: null,
          mapMode: "live",
          game: createScenarioState(Math.random, profile.campaignMode, profile.scenarioId),
          selectedBatteryId: null,
          placementKind: null,
        });
      },
      selectScenario: (scenarioId) => {
        const mode = get().pendingCampaignMode || "crisis";
        set({
          campaignMode: mode,
          pendingCampaignMode: null,
          mapMode: "live",
          game: createScenarioState(Math.random, mode, scenarioId),
          selectedBatteryId: null,
          placementKind: null,
        });
      },
      clearScenarioSelection: () => set({ pendingCampaignMode: null }),
      returnToModeSelect: () => set({ campaignMode: null, activeGameMode: null, pendingCampaignMode: null, placementKind: null, selectedBatteryId: null }),
      setMapMode: (mode) => set({ mapMode: mode }),
      dismissTutorial: () => {
        if (typeof window !== "undefined") {
          window.localStorage.setItem(tutorialKey, "true");
        }
        set({ tutorialDismissed: true });
      },
      setSelectedBattery: (batteryId) => set({ selectedBatteryId: batteryId, placementKind: null }),
      beginPlacement: (kind) => set({ placementKind: kind, selectedBatteryId: null }),
      cancelPlacement: () => set({ placementKind: null }),
      placeSelectedBattery: (position) => {
        const { game, placementKind } = get();
        if (!placementKind) return;
        const nextGame = placeBattery(game, placementKind, position);
        set({ game: nextGame, dailyCityGame: get().activeGameMode === "daily-defense" ? nextGame : get().dailyCityGame, placementKind: nextGame.placementWarning ? placementKind : null });
      },
      removeSelectedBattery: () => {
        const { game, selectedBatteryId } = get();
        if (!selectedBatteryId) return;
        const nextGame = removeBattery(game, selectedBatteryId);
        set({ game: nextGame, dailyCityGame: get().activeGameMode === "daily-defense" ? nextGame : get().dailyCityGame, selectedBatteryId: null });
      },
      startSelectedBatteryMaintenance: () => {
        const { game, selectedBatteryId } = get();
        if (!selectedBatteryId) return;
        const nextGame = setBatteryMaintenance(game, selectedBatteryId);
        set({ game: nextGame, dailyCityGame: get().activeGameMode === "daily-defense" ? nextGame : get().dailyCityGame });
      },
      togglePlanningAction: (actionId) => set((state) => { const game = togglePlanningAction(state.game, actionId); return { game, dailyCityGame: state.activeGameMode === "daily-defense" ? game : state.dailyCityGame }; }),
      tick: (deltaMs) => set((state) => ({ game: tickSimulation(state.game, deltaMs) })),
      resetCampaign: () => {
        const game = createScenarioState(Math.random, get().campaignMode || "crisis", get().game.scenarioId);
        set({ game, dailyCityGame: get().activeGameMode === "daily-defense" ? game : get().dailyCityGame, selectedBatteryId: null, placementKind: null });
      },
    }),
    {
      name: "shieldline-live-v7",
      version: 8,
      partialize: (state) => ({
        game: state.game,
        campaignMode: state.campaignMode,
        activeGameMode: state.activeGameMode,
        dailyCityGame: state.dailyCityGame,
        pendingCampaignMode: state.pendingCampaignMode,
        mapMode: state.mapMode,
        selectedBatteryId: state.selectedBatteryId,
      }),
    },
  ),
);
