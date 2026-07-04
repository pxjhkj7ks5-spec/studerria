import { RadioTower } from "lucide-react";
import { unitSprites } from "../assets/sprites/spriteCatalog";
import { getScenario } from "../data/scenarios";
import { unitDefinitions } from "../data/units";
import { useGameStore } from "../store/useGameStore";

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

function fatigueLabel(fatigue: number) {
  if (fatigue > 80) return "Exhausted";
  if (fatigue > 55) return "Strained";
  return "Nominal";
}

export function UnitRail() {
  const game = useGameStore((state) => state.game);
  const placementKind = useGameStore((state) => state.placementKind);
  const beginPlacement = useGameStore((state) => state.beginPlacement);
  const cancelPlacement = useGameStore((state) => state.cancelPlacement);
  const active = game.status === "active";
  const scenario = getScenario(game.scenarioId);

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
          const owned = game.batteries.filter((item) => item.kind === unit.kind).length;
          const allowed = scenario.allowedUnits.includes(unit.kind);
          const affordable = game.resources.budget >= unit.cost;
          const selected = placementKind === unit.kind;
          const localBattery = game.batteries.find((item) => item.kind === unit.kind);
          const readiness = localBattery ? localBattery.readiness : unit.readiness;
          const fatigue = localBattery ? localBattery.fatigue : 0;

          return (
            <article className={`unit-card ${selected ? "unit-card--selected" : ""}`} key={unit.kind} tabIndex={0}>
              <div className="unit-card__top">
                <img className="unit-sprite" src={unitSprites[unit.kind]} alt="" draggable="false" />
                <span>{owned}</span>
              </div>
              <strong>{unit.name}</strong>
              <p>{unit.description}</p>
              <small>Coverage {coverageLabel(unit.rangeLevel)} · {localBattery?.status || "ready"}</small>
              <div className="unit-hover-card" role="tooltip">
                <strong>{unit.shortName} detail</strong>
                <span>Detection +{unit.detectionBonus} · Intercept {unit.interceptionPower}</span>
                <span>Ammo use {unit.ammoUse} · Upkeep {unit.upkeep}</span>
                <span>Mobility {unit.mobility}/4 · Maintenance risk {maintenanceRisk(readiness)}</span>
                <span>Fatigue {Math.round(fatigue)}% · {fatigueLabel(fatigue)} · {localBattery?.supplyStatus || "not placed"}</span>
              </div>
              <div className="readiness-track" aria-label={`${unit.name} readiness`}>
                <i style={{ width: `${Math.round(readiness)}%` }} />
              </div>
              <div className={`fatigue-track fatigue-track--${fatigue > 70 ? "danger" : fatigue > 45 ? "warning" : "stable"}`} aria-label={`${unit.name} fatigue`}>
                <i style={{ width: `${Math.round(fatigue)}%` }} />
              </div>
              <div className="unit-card__actions">
                <button type="button" onClick={() => beginPlacement(unit.kind)} disabled={!active || !affordable || !allowed}>
                  {unit.cost}
                </button>
                <button type="button" onClick={() => beginPlacement(unit.kind)} disabled={!active || !affordable || !allowed}>
                  {allowed ? "Place" : "Locked"}
                </button>
              </div>
            </article>
          );
        })}
      </div>
    </>
  );
}
