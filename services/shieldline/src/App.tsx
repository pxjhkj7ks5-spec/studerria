import { useEffect, useRef, useState } from "react";
import { Activity, AlertTriangle, ClipboardList, Crosshair, Layers, Menu, Radio, RotateCcw, Settings, Shield, SlidersHorizontal, X, Zap } from "lucide-react";
import { AfterActionReport } from "./components/AfterActionReport";
import { ControlZoneAdmin } from "./components/ControlZoneAdmin";
import { IntelLog } from "./components/IntelLog";
import { MapLegend } from "./components/MapLegend";
import { ModeSelection } from "./components/ModeSelection";
import { PlanningActionsPanel } from "./components/PlanningActionsPanel";
import { ResourceBar } from "./components/ResourceBar";
import { ScenarioSelection } from "./components/ScenarioSelection";
import { TacticalMap } from "./components/TacticalMap";
import { TutorialOverlay } from "./components/TutorialOverlay";
import { UnitRail } from "./components/UnitRail";
import { CommandApp } from "./components/CommandApp";
import { getCampaignModeDefinition } from "./data/campaignModes";
import { getScenario } from "./data/scenarios";
import { getUnitDefinition } from "./data/units";
import { useGameStore } from "./store/useGameStore";
import type { CampaignStatus, DefenseBattery, MapMode, ThreatKind, UnitDefinition, UnitKind } from "./types/game";

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

const SIMULATION_TICK_MS = 300;

type ActivePanel = "layers" | "units" | "planning" | "intel" | "report" | "settings";

const panelItems: Array<{ id: ActivePanel; label: string; icon: typeof Layers }> = [
  { id: "layers", label: "Layers", icon: Layers },
  { id: "units", label: "Units", icon: Crosshair },
  { id: "planning", label: "Planning", icon: SlidersHorizontal },
  { id: "intel", label: "Intel", icon: Radio },
  { id: "report", label: "Report", icon: ClipboardList },
  { id: "settings", label: "Settings", icon: Settings },
];

const panelTitle: Record<ActivePanel, string> = {
  layers: "Map layers",
  units: "Defense units",
  planning: "Planning",
  intel: "Live intelligence",
  report: "After-action",
  settings: "Settings",
};

function formatAmmo(current: number | "infinite", capacity: number | "infinite") {
  if (capacity === "infinite" || current === "infinite") return "inf";
  return `${current}/${capacity}`;
}

function formatSeconds(ms: number) {
  if (ms <= 0) return "ready";
  return `${Math.ceil(ms / 1000)}s`;
}

export default function App() {
  const isAdminRoute = typeof window !== "undefined" && window.location.pathname.replace(/\/+$/, "").endsWith("/admin");
  if (isAdminRoute) {
    return <ControlZoneAdmin />;
  }
  const legacyRequested = typeof window !== "undefined" && new URLSearchParams(window.location.search).get("legacy") === "1";
  if (!legacyRequested) {
    return <CommandApp />;
  }

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
  const [activePanel, setActivePanel] = useState<ActivePanel | null>("units");
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
      if (accumulatorRef.current >= SIMULATION_TICK_MS) {
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
    <main className={`shell shell--map-first ${activePanel ? "shell--drawer-open" : "shell--drawer-closed"}`} aria-label="Shieldline real-time defense simulation">
      <nav className="app-rail" aria-label="Shieldline panels">
        <button className="rail-button rail-button--menu" type="button" aria-label="Back to scenario selection" onClick={returnToModeSelect}>
          <Menu size={24} />
        </button>
        <div className="rail-brand" aria-hidden="true">
          <Shield size={24} />
        </div>
        <div className="rail-button-stack">
          {panelItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                className={`rail-button ${activePanel === item.id ? "rail-button--active" : ""}`}
                type="button"
                key={item.id}
                onClick={() => setActivePanel((current) => (current === item.id ? null : item.id))}
                aria-label={item.label}
                aria-pressed={activePanel === item.id}
                title={item.label}
              >
                <Icon size={21} />
              </button>
            );
          })}
        </div>
      </nav>

      <section className={`map-stage map-stage--${mapMode} ${placementKind ? "map-stage--placing" : ""}`} aria-label="Live defense map">
        <TacticalMap />
        <header className="map-status-strip" aria-label="Campaign status">
          <div className="strip-brand">
            <Shield size={22} />
            <div>
              <h1>Shieldline</h1>
              <span>{scenario.title} · {modeDefinition?.title || "Live defense"} · {game.cyclePhase}</span>
            </div>
          </div>
          <ResourceBar game={game} />
        </header>
        <MapLegend mode={mapMode} />
      </section>

      {activePanel ? (
        <aside className={`command-drawer command-drawer--${activePanel}`} aria-label={`${panelTitle[activePanel]} panel`}>
          <div className="drawer-header">
            <div>
              <span>Shieldline</span>
              <strong>{panelTitle[activePanel]}</strong>
            </div>
            <button className="drawer-close" type="button" aria-label="Close side panel" onClick={() => setActivePanel(null)}>
              <X size={18} />
            </button>
          </div>
          {activePanel === "layers" ? (
            <section className="drawer-section">
              <div className="panel-layer-list">
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
              </div>
              <div className="live-stats live-stats--drawer" aria-label="Live defense telemetry">
                <span><strong>{game.day}</strong> Cycle</span>
                <span><strong>{revealedThreats}</strong> Revealed</span>
                <span><strong>{game.interceptions}</strong> Interceptions</span>
                <span><strong>{game.impacts}</strong> Impacts</span>
                <span><strong>{Math.round(game.wavePressure)}</strong> Pressure</span>
                <span><strong>{game.logistics.resupplyDelayDays}</strong> Supply delay</span>
              </div>
              {selectedBattery ? (
                <SelectedUnitPanel
                  selectedBattery={selectedBattery}
                  selectedUnit={selectedUnit}
                  onMaintain={startSelectedBatteryMaintenance}
                  onRecall={removeSelectedBattery}
                />
              ) : (
                <LiveStatusPanel placementKind={placementKind} placementWarning={game.placementWarning} />
              )}
            </section>
          ) : null}
          {activePanel === "units" ? <UnitRail /> : null}
          {activePanel === "planning" ? (
            <section className="drawer-section">
              <PlanningActionsPanel />
              {game.resources.ammo < 15 ? <AmmoLowCard /> : null}
            </section>
          ) : null}
          {activePanel === "intel" ? (
            <section className="drawer-section">
              <IntelLog game={game} />
              {game.status !== "active" ? <CampaignStatusCard status={game.status} statusReason={game.statusReason} /> : null}
            </section>
          ) : null}
          {activePanel === "report" ? (
            <section className="drawer-section">
              <AfterActionReport game={game} />
            </section>
          ) : null}
          {activePanel === "settings" ? (
            <section className="drawer-section">
              {selectedBattery ? (
                <SelectedUnitPanel
                  selectedBattery={selectedBattery}
                  selectedUnit={selectedUnit}
                  onMaintain={startSelectedBatteryMaintenance}
                  onRecall={removeSelectedBattery}
                />
              ) : (
                <LiveStatusPanel placementKind={placementKind} placementWarning={game.placementWarning} />
              )}
              <button className="reset-button" type="button" onClick={() => setConfirmReset(true)}>
                <RotateCcw size={16} />
                Reset Campaign
              </button>
              <button className="reset-button reset-button--secondary" type="button" onClick={returnToModeSelect}>
                <Menu size={16} />
                Change Scenario
              </button>
            </section>
          ) : null}
        </aside>
      ) : null}

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

function LiveStatusPanel({ placementKind, placementWarning }: { placementKind: UnitKind | null; placementWarning: string | null }) {
  return (
    <section className="live-card" aria-label="Live simulation status">
      <Zap size={22} />
      <div>
        <strong>{placementKind ? "Click an allowed area to place unit" : "Live Defense Active"}</strong>
        <span>{placementWarning || "Targets stay hidden until radar scan reveals them."}</span>
      </div>
    </section>
  );
}

function CampaignStatusCard({ status, statusReason }: { status: CampaignStatus; statusReason: string }) {
  return (
    <div className={`status-card status-card--${status}`}>
      <Activity size={22} />
      <div>
        <strong>{status === "won" ? "Campaign Stabilized" : "Campaign Failed"}</strong>
        <span>{statusReason}</span>
      </div>
    </div>
  );
}

function AmmoLowCard() {
  return (
    <div className="status-card status-card--lost">
      <AlertTriangle size={20} />
      <div>
        <strong>Ammo Low</strong>
        <span>Coverage remains active, but engagements are limited.</span>
      </div>
    </div>
  );
}

function SelectedUnitPanel({
  selectedBattery,
  selectedUnit,
  onMaintain,
  onRecall,
}: {
  selectedBattery: DefenseBattery;
  selectedUnit: UnitDefinition | null;
  onMaintain: () => void;
  onRecall: () => void;
}) {
  return (
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
        <button type="button" onClick={onMaintain} disabled={selectedBattery.status === "maintenance" || selectedBattery.status === "reloading"}>Maintain</button>
        <button type="button" onClick={onRecall}>Recall</button>
      </div>
    </section>
  );
}
