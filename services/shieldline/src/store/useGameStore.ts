import { create } from "zustand";
import { persist } from "zustand/middleware";
import { placeBattery, removeBattery, tickSimulation } from "../game/liveSimulation";
import { createInitialState } from "../game/initialState";
import type { CityId, Coordinates, GameState, UnitKind } from "../types/game";

interface GameStore {
  game: GameState;
  selectedCityId: CityId;
  selectedBatteryId: string | null;
  placementKind: UnitKind | null;
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
      selectedCityId: "kyiv",
      selectedBatteryId: null,
      placementKind: null,
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
        game: createInitialState(),
        selectedCityId: "kyiv",
        selectedBatteryId: null,
        placementKind: null,
      }),
    }),
    {
      name: "shieldline-live-v1",
      version: 2,
      partialize: (state) => ({
        game: state.game,
        selectedCityId: state.selectedCityId,
        selectedBatteryId: state.selectedBatteryId,
      }),
    },
  ),
);
