import { create } from "zustand";
import { persist } from "zustand/middleware";
import { placeBattery, removeBattery, setBatteryMaintenance, tickSimulation } from "../game/liveSimulation";
import { createInitialState, createScenarioState } from "../game/initialState";
import { togglePlanningAction } from "../game/planningActions";
import type { CampaignMode, CityId, Coordinates, GameState, MapMode, PlanningActionId, UnitKind } from "../types/game";

const tutorialKey = "shieldline-tutorial-complete-v1";

function readTutorialDismissed() {
  if (typeof window === "undefined") return false;
  return window.localStorage.getItem(tutorialKey) === "true";
}

interface GameStore {
  game: GameState;
  campaignMode: CampaignMode | null;
  pendingCampaignMode: CampaignMode | null;
  mapMode: MapMode;
  tutorialDismissed: boolean;
  selectedCityId: CityId;
  selectedBatteryId: string | null;
  placementKind: UnitKind | null;
  selectCampaignMode: (mode: CampaignMode) => void;
  selectScenario: (scenarioId: string) => void;
  clearScenarioSelection: () => void;
  returnToModeSelect: () => void;
  setMapMode: (mode: MapMode) => void;
  dismissTutorial: () => void;
  setSelectedCity: (cityId: CityId) => void;
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
      pendingCampaignMode: null,
      mapMode: "live",
      tutorialDismissed: readTutorialDismissed(),
      selectedCityId: "kyiv",
      selectedBatteryId: null,
      placementKind: null,
      selectCampaignMode: (mode) => set({
        pendingCampaignMode: mode,
      }),
      selectScenario: (scenarioId) => {
        const mode = get().pendingCampaignMode || "crisis";
        set({
          campaignMode: mode,
          pendingCampaignMode: null,
          mapMode: "live",
          game: createScenarioState(Math.random, mode, scenarioId),
          selectedCityId: "kyiv",
          selectedBatteryId: null,
          placementKind: null,
        });
      },
      clearScenarioSelection: () => set({ pendingCampaignMode: null }),
      returnToModeSelect: () => set({ campaignMode: null, pendingCampaignMode: null, placementKind: null, selectedBatteryId: null }),
      setMapMode: (mode) => set({ mapMode: mode }),
      dismissTutorial: () => {
        if (typeof window !== "undefined") {
          window.localStorage.setItem(tutorialKey, "true");
        }
        set({ tutorialDismissed: true });
      },
      setSelectedCity: (cityId) => set({ selectedCityId: cityId }),
      setSelectedBattery: (batteryId) => set({ selectedBatteryId: batteryId, placementKind: null }),
      beginPlacement: (kind) => set({ placementKind: kind, selectedBatteryId: null }),
      cancelPlacement: () => set({ placementKind: null }),
      placeSelectedBattery: (position) => {
        const { game, placementKind } = get();
        if (!placementKind) return;
        const nextGame = placeBattery(game, placementKind, position);
        set({ game: nextGame, placementKind: nextGame.placementWarning ? placementKind : null });
      },
      removeSelectedBattery: () => {
        const { game, selectedBatteryId } = get();
        if (!selectedBatteryId) return;
        set({ game: removeBattery(game, selectedBatteryId), selectedBatteryId: null });
      },
      startSelectedBatteryMaintenance: () => {
        const { game, selectedBatteryId } = get();
        if (!selectedBatteryId) return;
        set({ game: setBatteryMaintenance(game, selectedBatteryId) });
      },
      togglePlanningAction: (actionId) => set((state) => ({ game: togglePlanningAction(state.game, actionId) })),
      tick: (deltaMs) => set((state) => ({ game: tickSimulation(state.game, deltaMs) })),
      resetCampaign: () => set({
        game: createScenarioState(Math.random, get().campaignMode || "crisis", get().game.scenarioId),
        selectedCityId: "kyiv",
        selectedBatteryId: null,
        placementKind: null,
      }),
    }),
    {
      name: "shieldline-live-v6",
      version: 7,
      partialize: (state) => ({
        game: state.game,
        campaignMode: state.campaignMode,
        pendingCampaignMode: state.pendingCampaignMode,
        mapMode: state.mapMode,
        selectedCityId: state.selectedCityId,
        selectedBatteryId: state.selectedBatteryId,
      }),
    },
  ),
);
