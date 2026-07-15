import { useState } from "react";
import { RadioTower } from "lucide-react";
import { unitSprites } from "../assets/sprites/spriteCatalog";
import { getScenario } from "../data/scenarios";
import { unitDefinitions } from "../data/units";
import { tacticalUnitStatus } from "../game/unitStatusDisplay";
import { useGameStore } from "../store/useGameStore";
import type { ThreatKind, UnitDefinition } from "../types/game";

const chanceKinds: Array<{ kind: ThreatKind; label: string }> = [
  { kind: "geran2", label: "Geran" },
  { kind: "gerbera", label: "Gerbera" },
  { kind: "kh101", label: "X-101" },
  { kind: "iskander", label: "OTRK" },
];

function maintenanceRisk(readiness: number) {
  if (readiness < 70) return "високий";
  if (readiness < 84) return "помірний";
  return "низький";
}

function fatigueLabel(fatigue: number) {
  if (fatigue > 80) return "виснажена";
  if (fatigue > 55) return "напружена";
  return "нормальна";
}

function ammoLabel(unit: UnitDefinition, current?: number | "infinite") {
  if (unit.ammoCapacity === "infinite") return "∞";
  if (typeof current === "number") return `${current}/${unit.ammoCapacity}`;
  return `${unit.ammoCapacity}`;
}

function seconds(ms: number) {
  return `${(ms / 1000).toFixed(ms < 2000 ? 1 : 0)} с`;
}

function keepExpandedCardVisible(card: HTMLElement) {
  const alignCard = () => {
    const list = card.parentElement;
    if (!list) return;
    const cardRect = card.getBoundingClientRect();
    const listRect = list.getBoundingClientRect();
    const overflow = cardRect.bottom - listRect.bottom + 8;
    const behavior = window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth";
    if (overflow > 0) list.scrollBy({ top: overflow, behavior });
  };
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  window.requestAnimationFrame(alignCard);
  window.setTimeout(alignCard, reducedMotion ? 0 : 240);
}

export function UnitRail({ onPlacementStart }: { onPlacementStart?: () => void }) {
  const [expandedKind, setExpandedKind] = useState<UnitDefinition["kind"] | null>(null);
  const game = useGameStore((state) => state.game);
  const placementKind = useGameStore((state) => state.placementKind);
  const beginPlacement = useGameStore((state) => state.beginPlacement);
  const cancelPlacement = useGameStore((state) => state.cancelPlacement);
  const serviceBattery = useGameStore((state) => state.serviceCampaignBattery);
  const active = game.status === "active";
  const scenario = getScenario(game.scenarioId);
  const storedBatteries = game.storedBatteries || [];
  const expandCard = (card: HTMLElement, kind: UnitDefinition["kind"]) => {
    const details = card.querySelector<HTMLElement>(".unit-hover-card__content");
    card.style.setProperty("--unit-details-height", `${(details?.scrollHeight || 0) + 24}px`);
    setExpandedKind(kind);
    keepExpandedCardVisible(card);
  };

  return (
    <>
      <div className="unit-actions">
        <button className="redeploy-button" type="button" onClick={cancelPlacement} disabled={!placementKind}>
          <RadioTower size={16} />
          Скасувати розміщення
        </button>
        <span>Розміщено ППО: {game.batteries.length}</span>
        {game.placementWarning ? <strong className="placement-warning">{game.placementWarning}</strong> : null}
      </div>
      <div className="unit-list">
        {unitDefinitions.map((unit) => {
          const allowed = scenario.allowedUnits.includes(unit.kind) && (!game.campaign || game.campaign.unlockedSystems.includes(unit.kind));
          const storedUnits = storedBatteries.filter((item) => item.kind === unit.kind);
          const storedBattery = storedUnits[0];
          const affordable = storedUnits.length > 0 || game.resources.budget >= unit.cost;
          const selected = placementKind === unit.kind;
          const disabled = !active || !affordable || !allowed;
          const localBattery = game.batteries.find((item) => item.kind === unit.kind);
          const referenceBattery = localBattery || storedBattery;
          const readiness = referenceBattery ? referenceBattery.readiness : unit.readiness;
          const fatigue = referenceBattery ? referenceBattery.fatigue : 0;
          const reloadText = referenceBattery?.reloadRemainingMs ? seconds(referenceBattery.reloadRemainingMs) : seconds(unit.reloadMs);
          const ammoText = ammoLabel(unit, referenceBattery?.currentAmmo);
          const tacticalStatus = tacticalUnitStatus(unit, referenceBattery);
          const isRadar = unit.engagementMode === "detect";
          const showStatus = tacticalStatus.label !== "READY";

          return (
            <article
              className={`unit-card unit-card--state-${tacticalStatus.tone} ${isRadar ? "unit-card--radar" : ""} ${showStatus ? "unit-card--has-status" : ""} ${storedUnits.length ? "unit-card--has-storage" : ""} ${expandedKind === unit.kind ? "unit-card--expanded" : ""} ${selected ? "unit-card--selected" : ""} ${disabled ? "unit-card--disabled" : ""}`}
              key={unit.kind}
              tabIndex={0}
              role="button"
              aria-disabled={disabled}
              onMouseEnter={(event) => expandCard(event.currentTarget, unit.kind)}
              onMouseLeave={() => setExpandedKind((current) => current === unit.kind ? null : current)}
              onFocus={(event) => expandCard(event.currentTarget, unit.kind)}
              onBlur={(event) => {
                if (!event.currentTarget.contains(event.relatedTarget)) setExpandedKind((current) => current === unit.kind ? null : current);
              }}
              onClick={() => {
                if (!disabled) { beginPlacement(unit.kind); onPlacementStart?.(); }
              }}
              onKeyDown={(event) => {
                if ((event.key === "Enter" || event.key === " ") && !disabled) {
                  event.preventDefault();
                  beginPlacement(unit.kind); onPlacementStart?.();
                }
              }}
            >
              <div className="unit-card__top">
                <img className="unit-sprite" src={unitSprites[unit.kind]} alt="" draggable="false" />
                {storedUnits.length || showStatus ? <div className="unit-card__badges">
                  {storedUnits.length ? <span className="unit-card__storage">На складі · {storedUnits.length}</span> : null}
                  {showStatus ? <span className={`unit-status unit-status--${tacticalStatus.tone}`}>{tacticalStatus.label}</span> : null}
                </div> : null}
              </div>
              <strong>{unit.name}</strong>
              <span className="unit-card__code">{unit.technicalCode}</span>
              <p>{unit.description}</p>
              <div className={`unit-card__telemetry ${isRadar ? "unit-card__telemetry--radar" : ""}`}>
                {!isRadar ? <span><small>БК</small><b>{ammoText}</b></span> : null}
                <span><small>{isRadar ? "Радіус" : "Зона"}</small><b>{isRadar ? `${unit.outerRangeKm} км` : `${unit.primaryRangeKm}/${unit.outerRangeKm} км`}</b></span>
                <span><small>Вартість</small><b>{storedUnits.length ? "0 ₴" : unit.costLabel}</b></span>
              </div>
              <div className="unit-chance-row" aria-label={`Імовірність ураження для ${unit.name}`}>
                {chanceKinds.map(({ kind, label }) => (
                  <span key={kind} className={unit.engagementChanceByThreat[kind] <= 0 ? "unit-chance--muted" : ""}>
                    <b>{Math.round(unit.engagementChanceByThreat[kind])}%</b>
                    {label}
                  </span>
                ))}
              </div>
              <div className="unit-hover-card" role="tooltip">
                <div className="unit-hover-card__content">
                  <strong>Дані {unit.shortName}</strong>
                  {isRadar ? (
                    <>
                      <span>Радіус виявлення {unit.outerRangeKm} км</span>
                      <span>Бонус виявлення {unit.detectionBonus}%</span>
                    </>
                  ) : (
                    <>
                      <span>Основна зона {unit.primaryRangeKm} км · зовнішня {unit.outerRangeKm} км</span>
                      <span>БК {ammoText} · перезаряджання {reloadText} · пауза {seconds(unit.shotCooldownMs)}</span>
                      <span>Точність: {unit.primaryAccuracy}% · зовнішня зона {unit.outerAccuracy}%</span>
                    </>
                  )}
                  <span>Мобільність {unit.mobility}/4 · ризик обслуговування {maintenanceRisk(readiness)}</span>
                  <span>Готовність {Math.round(readiness)}% · втома {Math.round(fatigue)}% ({fatigueLabel(fatigue)})</span>
                  {referenceBattery ? <span>Стан {Math.round(referenceBattery.health)}% · досвід L{referenceBattery.experienceLevel}</span> : null}
                  <span>{storedBattery ? "На складі" : localBattery?.supplyStatus || "Не розміщена"}</span>
                  {game.campaign?.intermission && referenceBattery ? <div className="campaign-service-actions"><button type="button" onClick={(event) => { event.stopPropagation(); serviceBattery(referenceBattery.id, "resupply", .5); }}>+50% БК</button><button type="button" onClick={(event) => { event.stopPropagation(); serviceBattery(referenceBattery.id, "repair", 1); }}>Ремонт</button></div> : null}
                </div>
              </div>
              <div className={`fatigue-track fatigue-track--${fatigue > 70 ? "danger" : fatigue > 45 ? "warning" : "stable"}`} aria-label={`Втома ${unit.name}`}>
                <i style={{ width: `${Math.round(fatigue)}%` }} />
              </div>
              <div className="unit-card__meta">
                <span>{storedUnits.length ? "зі складу" : `${unit.cost} млн`}</span>
                <span>{allowed ? selected ? "обрано" : storedUnits.length ? "розмістити" : affordable ? "обрати" : "бракує бюджету" : "недоступно"}</span>
              </div>
            </article>
          );
        })}
      </div>
    </>
  );
}
