import { RadioTower } from "lucide-react";
import { unitSprites } from "../assets/sprites/spriteCatalog";
import { getScenario } from "../data/scenarios";
import { unitDefinitions } from "../data/units";
import { useGameStore } from "../store/useGameStore";
import type { ThreatKind, UnitDefinition } from "../types/game";

const chanceKinds: Array<{ kind: ThreatKind; label: string }> = [
  { kind: "drone", label: "БпЛА" },
  { kind: "cruise", label: "КР" },
  { kind: "ballistic", label: "Баліст." },
  { kind: "decoy", label: "Хибн." },
];

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

function ammoLabel(unit: UnitDefinition, current?: number | "infinite") {
  if (unit.ammoCapacity === "infinite") return "∞";
  if (typeof current === "number") return `${current}/${unit.ammoCapacity}`;
  return `${unit.ammoCapacity}`;
}

function seconds(ms: number) {
  return `${(ms / 1000).toFixed(ms < 2000 ? 1 : 0)}s`;
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
          const reloadText = localBattery?.reloadRemainingMs ? seconds(localBattery.reloadRemainingMs) : seconds(unit.reloadMs);
          const ammoText = ammoLabel(unit, localBattery?.currentAmmo);

          return (
            <article className={`unit-card ${selected ? "unit-card--selected" : ""}`} key={unit.kind} tabIndex={0}>
              <div className="unit-card__top">
                <img className="unit-sprite" src={unitSprites[unit.kind]} alt="" draggable="false" />
                <span className="ammo-badge">{ammoText}</span>
              </div>
              <strong>{unit.name}</strong>
              <p>{unit.description}</p>
              <small>{unit.costLabel} · {unit.primaryRangeKm}/{unit.outerRangeKm} км · {localBattery?.status || "ready"}</small>
              <div className="unit-chance-row" aria-label={`${unit.name} hit chances`}>
                {chanceKinds.map(({ kind, label }) => (
                  <span key={kind} className={unit.engagementChanceByThreat[kind] <= 0 ? "unit-chance--muted" : ""}>
                    <b>{Math.round(unit.engagementChanceByThreat[kind])}%</b>
                    {label}
                  </span>
                ))}
              </div>
              <div className="unit-hover-card" role="tooltip">
                <strong>{unit.shortName} detail</strong>
                <span>Primary {unit.primaryRangeKm} км · Outer {unit.outerRangeKm} км</span>
                <span>БК {ammoText} · Reload {reloadText} · Shot pause {seconds(unit.shotCooldownMs)}</span>
                <span>Primary acc {unit.primaryAccuracy}% · Outer acc {unit.outerAccuracy}%</span>
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
