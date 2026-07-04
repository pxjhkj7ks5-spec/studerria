import { create } from "zustand";
import { persist } from "zustand/middleware";
import { placeBattery, removeBattery, tickSimulation } from "../game/liveSimulation";
import { createInitialState } from "../game/initialState";
import type { CampaignMode, CityId, Coordinates, GameState, MapMode, UnitKind } from "../types/game";

const tutorialKey = "shieldline-tutorial-complete-v1";

function readTutorialDismissed() {
  if (typeof window === "undefined") return false;
  return window.localStorage.getItem(tutorialKey) === "true";
}

interface GameStore {
  game: GameState;
  campaignMode: CampaignMode | null;
  mapMode: MapMode;
  tutorialDismissed: boolean;
  selectedCityId: CityId;
  selectedBatteryId: string | null;
  placementKind: UnitKind | null;
  selectCampaignMode: (mode: CampaignMode) => void;
  returnToModeSelect: () => void;
  setMapMode: (mode: MapMode) => void;
  dismissTutorial: () => void;
  setSelectedCity: (cityId: CityId) => void;
  setSelectedBattery: (batteryId: string | null) => void;
  beginPlacement: (kind: UnitKind) => void;
  cancelPlacement: () => void;
  placeSelectedBattery: (position: Coordinates) => void;
  removeSelectedBattery: () => void;
  tick: (deltaMs: number) => void;
  resetCampaign: () => void;
}

export const useGameStore = create<GameStore>()(
  persist(
    (set, get) => ({
      game: createInitialState(),
      campaignMode: null,
      mapMode: "live",
      tutorialDismissed: readTutorialDismissed(),
      selectedCityId: "kyiv",
      selectedBatteryId: null,
      placementKind: null,
      selectCampaignMode: (mode) => set({
        campaignMode: mode,
        mapMode: "live",
        game: createInitialState(Math.random, mode),
        selectedCityId: "kyiv",
        selectedBatteryId: null,
        placementKind: null,
      }),
      returnToModeSelect: () => set({ campaignMode: null, placementKind: null, selectedBatteryId: null }),
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
        set({ game: placeBattery(game, placementKind, position), placementKind: null });
      },
      removeSelectedBattery: () => {
        const { game, selectedBatteryId } = get();
        if (!selectedBatteryId) return;
        set({ game: removeBattery(game, selectedBatteryId), selectedBatteryId: null });
      },
      tick: (deltaMs) => set((state) => ({ game: tickSimulation(state.game, deltaMs) })),
      resetCampaign: () => set({
        game: createInitialState(Math.random, get().campaignMode || "crisis"),
        selectedCityId: "kyiv",
        selectedBatteryId: null,
        placementKind: null,
      }),
    }),
    {
      name: "shieldline-live-v3",
      version: 4,
      partialize: (state) => ({
        game: state.game,
        campaignMode: state.campaignMode,
        mapMode: state.mapMode,
        selectedCityId: state.selectedCityId,
        selectedBatteryId: state.selectedBatteryId,
      }),
    },
  ),
);
