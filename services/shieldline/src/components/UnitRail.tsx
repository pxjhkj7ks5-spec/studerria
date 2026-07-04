import {
  CloudFog,
  Crosshair,
  Radar,
  RadioTower,
  Satellite,
  Shield,
  Truck,
  Wrench,
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

function coverageLabel(rangeLevel: number) {
  if (rangeLevel >= 3) return "III";
  if (rangeLevel >= 2) return "II";
  return "I";
}

function maintenanceRisk(readiness: number) {
  if (readiness < 70) return "Elevated";
  if (readiness < 84) return "Moderate";
  return "Low";
}

export function UnitRail() {
  const game = useGameStore((state) => state.game);
  const placementKind = useGameStore((state) => state.placementKind);
  const beginPlacement = useGameStore((state) => state.beginPlacement);
  const cancelPlacement = useGameStore((state) => state.cancelPlacement);
  const active = game.status === "active";

  return (
    <>
      <div className="unit-actions">
        <button className="redeploy-button" type="button" onClick={cancelPlacement} disabled={!placementKind}>
          <RadioTower size={16} />
          Cancel placement
        </button>
        <span>{game.batteries.length} placed ППО units</span>
      </div>
      <div className="unit-list">
        {unitDefinitions.map((unit) => {
          const Icon = unitIcons[unit.kind];
          const owned = game.batteries.filter((item) => item.kind === unit.kind).length;
          const affordable = game.resources.budget >= unit.cost;
          const selected = placementKind === unit.kind;
          const localBattery = game.batteries.find((item) => item.kind === unit.kind);
          const readiness = localBattery ? localBattery.readiness : unit.readiness;

          return (
            <article className={`unit-card ${selected ? "unit-card--selected" : ""}`} key={unit.kind} tabIndex={0}>
              <div className="unit-card__top">
                <Icon size={28} />
                <span>{owned}</span>
              </div>
              <strong>{unit.name}</strong>
              <p>{unit.description}</p>
              <small>Coverage {coverageLabel(unit.rangeLevel)}</small>
              <div className="unit-hover-card" role="tooltip">
                <strong>{unit.shortName} detail</strong>
                <span>Detection +{unit.detectionBonus} · Intercept {unit.interceptionPower}</span>
                <span>Ammo use {unit.ammoUse} · Upkeep {unit.upkeep}</span>
                <span>Mobility {unit.mobility}/4 · Maintenance risk {maintenanceRisk(readiness)}</span>
              </div>
              <div className="readiness-track" aria-label={`${unit.name} readiness`}>
                <i style={{ width: `${Math.round(readiness)}%` }} />
              </div>
              <div className="unit-card__actions">
                <button type="button" onClick={() => beginPlacement(unit.kind)} disabled={!active || !affordable}>
                  {unit.cost}
                </button>
                <button type="button" onClick={() => beginPlacement(unit.kind)} disabled={!active || !affordable}>
                  Place
                </button>
              </div>
            </article>
          );
        })}
      </div>
    </>
  );
}
