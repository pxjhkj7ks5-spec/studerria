import { useEffect, useRef, useState } from "react";
import { Activity, AlertTriangle, Crosshair, Menu, RotateCcw, Shield, Zap } from "lucide-react";
import { AfterActionReport } from "./components/AfterActionReport";
import { IntelLog } from "./components/IntelLog";
import { MapLegend } from "./components/MapLegend";
import { ModeSelection } from "./components/ModeSelection";
import { PlanningActionsPanel } from "./components/PlanningActionsPanel";
import { ResourceBar } from "./components/ResourceBar";
import { ScenarioSelection } from "./components/ScenarioSelection";
import { TacticalMap } from "./components/TacticalMap";
import { TutorialOverlay } from "./components/TutorialOverlay";
import { UnitRail } from "./components/UnitRail";
import { getCampaignModeDefinition } from "./data/campaignModes";
import { getScenario } from "./data/scenarios";
import { getUnitDefinition } from "./data/units";
import { useGameStore } from "./store/useGameStore";
import type { MapMode, ThreatKind } from "./types/game";

const mapModes: Array<{ id: MapMode; label: string }> = [
  { id: "live", label: "Live" },
  { id: "threats", label: "Threats" },
  { id: "coverage", label: "Coverage" },
  { id: "logistics", label: "Logistics" },
];

const threatLabels: Array<{ kind: ThreatKind; label: string }> = [
  { kind: "geran2", label: "Geran" },
  { kind: "gerbera", label: "Gerbera" },
  { kind: "kh101", label: "X-101" },
  { kind: "iskander", label: "OTRK" },
];

function formatAmmo(current: number | "infinite", capacity: number | "infinite") {
  if (capacity === "infinite" || current === "infinite") return "inf";
  return `${current}/${capacity}`;
}

function formatSeconds(ms: number) {
  if (ms <= 0) return "ready";
  return `${Math.ceil(ms / 1000)}s`;
}

export default function App() {
  const game = useGameStore((state) => state.game);
  const campaignMode = useGameStore((state) => state.campaignMode);
  const pendingCampaignMode = useGameStore((state) => state.pendingCampaignMode);
  const mapMode = useGameStore((state) => state.mapMode);
  const tutorialDismissed = useGameStore((state) => state.tutorialDismissed);
  const selectCampaignMode = useGameStore((state) => state.selectCampaignMode);
  const selectScenario = useGameStore((state) => state.selectScenario);
  const clearScenarioSelection = useGameStore((state) => state.clearScenarioSelection);
  const returnToModeSelect = useGameStore((state) => state.returnToModeSelect);
  const setMapMode = useGameStore((state) => state.setMapMode);
  const dismissTutorial = useGameStore((state) => state.dismissTutorial);
  const resetCampaign = useGameStore((state) => state.resetCampaign);
  const tick = useGameStore((state) => state.tick);
  const removeSelectedBattery = useGameStore((state) => state.removeSelectedBattery);
  const startSelectedBatteryMaintenance = useGameStore((state) => state.startSelectedBatteryMaintenance);
  const selectedBatteryId = useGameStore((state) => state.selectedBatteryId);
  const placementKind = useGameStore((state) => state.placementKind);
  const [confirmReset, setConfirmReset] = useState(false);
  const selectedBattery = game.batteries.find((battery) => battery.id === selectedBatteryId) || null;
  const selectedUnit = selectedBattery ? getUnitDefinition(selectedBattery.kind) : null;
  const modeDefinition = campaignMode ? getCampaignModeDefinition(campaignMode) : null;
  const scenario = getScenario(game.scenarioId);
  const lastTickRef = useRef<number | null>(null);
  const accumulatorRef = useRef(0);
  const revealedThreats = game.liveThreats.filter((threat) => threat.revealed).length;

  useEffect(() => {
    if (!campaignMode) return undefined;
    let frameId = 0;
    const frame = (timestamp: number) => {
      if (lastTickRef.current === null) {
        lastTickRef.current = timestamp;
      }
      const delta = timestamp - lastTickRef.current;
      lastTickRef.current = timestamp;
      accumulatorRef.current += delta;
      if (accumulatorRef.current >= 180) {
        tick(accumulatorRef.current);
        accumulatorRef.current = 0;
      }
      frameId = window.requestAnimationFrame(frame);
    };
    frameId = window.requestAnimationFrame(frame);
    return () => window.cancelAnimationFrame(frameId);
  }, [campaignMode, tick]);

  if (!campaignMode && pendingCampaignMode) {
    return <ScenarioSelection onSelect={selectScenario} onBack={clearScenarioSelection} />;
  }

  if (!campaignMode) {
    return <ModeSelection onSelect={selectCampaignMode} />;
  }

  return (
    <main className="shell" aria-label="Shieldline real-time defense simulation">
      <header className="topbar">
        <div className="brand-card">
          <button className="icon-button" type="button" aria-label="Shieldline menu" onClick={returnToModeSelect}>
            <Menu size={24} />
          </button>
          <div className="brand-mark" aria-hidden="true">
            <Shield size={28} />
          </div>
          <div>
            <h1>Shieldline</h1>
            <span>{scenario.title} · {modeDefinition?.title || "Live defense"} · {game.cyclePhase}</span>
          </div>
        </div>
        <ResourceBar game={game} />
      </header>

      <section className={`map-stage map-stage--${mapMode} ${placementKind ? "map-stage--placing" : ""}`} aria-label="Live defense map">
        <TacticalMap />
        <aside className="left-rail" aria-label="Map layers">
          {mapModes.map((mode) => (
            <button
              className={`nav-pill ${mapMode === mode.id ? "nav-pill--active" : ""}`}
              type="button"
              key={mode.id}
              onClick={() => setMapMode(mode.id)}
            >
              {mode.label}
            </button>
          ))}
        </aside>
        <MapLegend mode={mapMode} />
      </section>

      <aside className="right-panel" aria-label="Live intelligence and event log">
        <IntelLog game={game} />
        {game.status !== "active" ? (
          <div className={`status-card status-card--${game.status}`}>
            <Activity size={22} />
            <div>
              <strong>{game.status === "won" ? "Campaign Stabilized" : "Campaign Failed"}</strong>
              <span>{game.statusReason}</span>
            </div>
          </div>
        ) : null}
        {selectedBattery ? (
          <section className="selected-unit-card" aria-label="Selected defense unit">
            <div className="selected-unit-card__head">
              <Crosshair size={22} />
              <div>
                <strong>{selectedUnit?.name || "Selected PPO"}</strong>
                <span>{selectedBattery.status} · {selectedBattery.supplyStatus} · last: {selectedBattery.lastEngagementResult}</span>
              </div>
            </div>
            {selectedUnit ? (
              <>
                <div className="selected-unit-grid">
                  <span><b>{selectedUnit.primaryRangeKm} km</b> primary</span>
                  <span><b>{selectedUnit.outerRangeKm} km</b> outer</span>
                  <span><b>{formatAmmo(selectedBattery.currentAmmo, selectedUnit.ammoCapacity)}</b> ammo</span>
                  <span><b>{formatSeconds(selectedBattery.reloadRemainingMs)}</b> reload</span>
                  <span><b>{formatSeconds(selectedBattery.cooldownMs)}</b> cooldown</span>
                  <span><b>{Math.round(selectedBattery.readiness)}%</b> readiness</span>
                  <span><b>{Math.round(selectedBattery.fatigue)}%</b> fatigue</span>
                  <span><b>{selectedUnit.primaryAccuracy}%</b> primary acc</span>
                  <span><b>{selectedUnit.outerAccuracy}%</b> outer acc</span>
                </div>
                <div className="chance-grid" aria-label="Threat-specific hit chances">
                  {threatLabels.map(({ kind, label }) => (
                    <span key={kind}>
                      <b>{Math.round(selectedUnit.engagementChanceByThreat[kind])}%</b>
                      {label}
                    </span>
                  ))}
                </div>
              </>
            ) : null}
            <div className="selected-unit-card__actions">
              <button type="button" onClick={startSelectedBatteryMaintenance} disabled={selectedBattery.status === "maintenance" || selectedBattery.status === "reloading"}>Maintain</button>
              <button type="button" onClick={removeSelectedBattery}>Recall</button>
            </div>
          </section>
        ) : (
          <section className="live-card" aria-label="Live simulation status">
            <Zap size={22} />
            <div>
              <strong>{placementKind ? "Click controlled map area to place PPO" : "Live Defense Active"}</strong>
              <span>{game.placementWarning || "Targets stay hidden until radar scan reveals them."}</span>
            </div>
          </section>
        )}
        <div className="live-stats" aria-label="Live defense telemetry">
          <span><strong>{game.day}</strong> Cycle</span>
          <span><strong>{revealedThreats}</strong> Revealed</span>
          <span><strong>{game.interceptions}</strong> Interceptions</span>
          <span><strong>{game.impacts}</strong> Impacts</span>
          <span><strong>{Math.round(game.wavePressure)}</strong> Pressure</span>
          <span><strong>{game.logistics.resupplyDelayDays}</strong> Supply delay</span>
        </div>
        <PlanningActionsPanel />
        <AfterActionReport game={game} />
        {game.resources.ammo < 15 ? (
          <div className="status-card status-card--lost">
            <AlertTriangle size={20} />
            <div>
              <strong>Ammo Low</strong>
              <span>Coverage remains active, but engagements are limited.</span>
            </div>
          </div>
        ) : null}
        <button className="reset-button" type="button" onClick={() => setConfirmReset(true)}>
          <RotateCcw size={16} />
          Reset Campaign
        </button>
      </aside>

      <footer className="unit-dock" aria-label="Defense placement cards">
        <UnitRail />
      </footer>

      {!tutorialDismissed ? <TutorialOverlay onDismiss={dismissTutorial} /> : null}
      {confirmReset ? (
        <div className="confirm-overlay" role="dialog" aria-modal="true" aria-label="Reset campaign confirmation">
          <section className="confirm-card">
            <strong>Reset campaign?</strong>
            <span>This clears live threats, placements, and current resource state for this scenario.</span>
            <div>
              <button type="button" onClick={() => setConfirmReset(false)}>Cancel</button>
              <button
                type="button"
                onClick={() => {
                  resetCampaign();
                  setConfirmReset(false);
                }}
              >
                Reset
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </main>
  );
}
