import {
  Crosshair,
  RadioTower,
  Radar,
  Satellite,
  Shield,
  Truck,
  Wrench,
  CloudFog,
} from "lucide-react";
import { unitDefinitions } from "../data/units";
import { useGameStore } from "../store/useGameStore";
import type { UnitKind } from "../types/game";

const unitIcons: Record<UnitKind, typeof Radar> = {
  radar: Radar,
  mobile: Truck,
  short: Shield,
  medium: Crosshair,
  repair: Wrench,
  logistics: Truck,
  intel: Satellite,
  decoy: CloudFog,
};

export function UnitRail() {
  const game = useGameStore((state) => state.game);
  const selectedCityId = useGameStore((state) => state.selectedCityId);
  const selectedUnitId = useGameStore((state) => state.selectedUnitId);
  const setSelectedUnit = useGameStore((state) => state.setSelectedUnit);
  const buyUnit = useGameStore((state) => state.buyUnit);
  const redeploySelectedUnit = useGameStore((state) => state.redeploySelectedUnit);
  const cityUnits = game.units.filter((unit) => unit.cityId === selectedCityId);
  const active = game.status === "active";

  return (
    <>
      <div className="unit-actions">
        <button
          className="redeploy-button"
          type="button"
          onClick={redeploySelectedUnit}
          disabled={!active || !selectedUnitId}
        >
          <RadioTower size={16} />
          Redeploy selected
        </button>
        <span>{cityUnits.length} local units</span>
      </div>
      <div className="unit-list">
        {unitDefinitions.map((unit) => {
          const Icon = unitIcons[unit.kind];
          const owned = game.units.filter((item) => item.kind === unit.kind).length;
          const affordable = game.resources.budget >= unit.cost;
          const selectedUnit = cityUnits.find((item) => item.kind === unit.kind && item.id === selectedUnitId);
          const readiness = selectedUnit
            ? selectedUnit.readiness
            : cityUnits.find((item) => item.kind === unit.kind)?.readiness || unit.readiness;

          return (
            <article className="unit-card" key={unit.kind}>
              <div className="unit-card__top">
                <Icon size={28} />
                <span>{owned}</span>
              </div>
              <strong>{unit.name}</strong>
              <p>{unit.description}</p>
              <div className="readiness-track" aria-label={`${unit.name} readiness`}>
                <i style={{ width: `${Math.round(readiness)}%` }} />
              </div>
              <div className="unit-card__actions">
                <button type="button" onClick={() => buyUnit(unit.kind)} disabled={!active || !affordable}>
                  {unit.cost}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const local = cityUnits.find((item) => item.kind === unit.kind);
                    setSelectedUnit(local ? local.id : null);
                  }}
                  disabled={!cityUnits.some((item) => item.kind === unit.kind)}
                >
                  Select
                </button>
              </div>
            </article>
          );
        })}
      </div>
    </>
  );
}
