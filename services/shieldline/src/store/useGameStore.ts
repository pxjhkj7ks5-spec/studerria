import { create } from "zustand";
import { persist } from "zustand/middleware";
import { advanceDay, moveUnit, purchaseUnit } from "../game/simulation";
import { createInitialState } from "../game/initialState";
import type { CityId, GameState, UnitKind } from "../types/game";

interface GameStore {
  game: GameState;
  selectedCityId: CityId;
  selectedUnitId: string | null;
  setSelectedCity: (cityId: CityId) => void;
  setSelectedUnit: (unitId: string | null) => void;
  buyUnit: (kind: UnitKind) => void;
  redeploySelectedUnit: () => void;
  nextDay: () => void;
  resetCampaign: () => void;
}

export const useGameStore = create<GameStore>()(
  persist(
    (set, get) => ({
      game: createInitialState(),
      selectedCityId: "kyiv",
      selectedUnitId: null,
      setSelectedCity: (cityId) => set({ selectedCityId: cityId }),
      setSelectedUnit: (unitId) => set({ selectedUnitId: unitId }),
      buyUnit: (kind) => {
        const { game, selectedCityId } = get();
        set({ game: purchaseUnit(game, kind, selectedCityId) });
      },
      redeploySelectedUnit: () => {
        const { game, selectedCityId, selectedUnitId } = get();
        if (!selectedUnitId) return;
        set({ game: moveUnit(game, selectedUnitId, selectedCityId), selectedUnitId: null });
      },
      nextDay: () => set((state) => ({ game: advanceDay(state.game), selectedUnitId: null })),
      resetCampaign: () => set({ game: createInitialState(), selectedCityId: "kyiv", selectedUnitId: null }),
    }),
    {
      name: "shieldline-campaign-v1",
      version: 1,
      partialize: (state) => ({
        game: state.game,
        selectedCityId: state.selectedCityId,
      }),
    },
  ),
);
