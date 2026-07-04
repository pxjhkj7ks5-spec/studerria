import { useEffect, useRef, useState } from "react";
import { Activity, AlertTriangle, Crosshair, Menu, RotateCcw, Shield, Zap } from "lucide-react";
import { AfterActionReport } from "./components/AfterActionReport";
import { CityPanel } from "./components/CityPanel";
import { IntelLog } from "./components/IntelLog";
import { MapLegend } from "./components/MapLegend";
import { ModeSelection } from "./components/ModeSelection";
import { ResourceBar } from "./components/ResourceBar";
import { TacticalMap } from "./components/TacticalMap";
import { TutorialOverlay } from "./components/TutorialOverlay";
import { UnitRail } from "./components/UnitRail";
import { getCampaignModeDefinition } from "./data/campaignModes";
import { useGameStore } from "./store/useGameStore";
import type { MapMode } from "./types/game";

const mapModes: Array<{ id: MapMode; label: string }> = [
  { id: "live", label: "Live" },
  { id: "threats", label: "Threats" },
  { id: "coverage", label: "Coverage" },
  { id: "logistics", label: "Logistics" },
];

export default function App() {
  const game = useGameStore((state) => state.game);
  const campaignMode = useGameStore((state) => state.campaignMode);
  const mapMode = useGameStore((state) => state.mapMode);
  const tutorialDismissed = useGameStore((state) => state.tutorialDismissed);
  const selectCampaignMode = useGameStore((state) => state.selectCampaignMode);
  const returnToModeSelect = useGameStore((state) => state.returnToModeSelect);
  const setMapMode = useGameStore((state) => state.setMapMode);
  const dismissTutorial = useGameStore((state) => state.dismissTutorial);
  const resetCampaign = useGameStore((state) => state.resetCampaign);
  const tick = useGameStore((state) => state.tick);
  const removeSelectedBattery = useGameStore((state) => state.removeSelectedBattery);
  const selectedCityId = useGameStore((state) => state.selectedCityId);
  const selectedBatteryId = useGameStore((state) => state.selectedBatteryId);
  const placementKind = useGameStore((state) => state.placementKind);
  const [confirmReset, setConfirmReset] = useState(false);
  const selectedCity = game.cities.find((city) => city.id === selectedCityId) || game.cities[0];
  const selectedBattery = game.batteries.find((battery) => battery.id === selectedBatteryId) || null;
  const modeDefinition = campaignMode ? getCampaignModeDefinition(campaignMode) : null;
  const lastTickRef = useRef<number | null>(null);
  const accumulatorRef = useRef(0);

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
            <span>{modeDefinition?.title || "Live defense"} · command watch</span>
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
        <CityPanel city={selectedCity} game={game} />
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
          <section className="live-card" aria-label="Selected defense unit">
            <Crosshair size={22} />
            <div>
              <strong>Selected ППО</strong>
              <span>Coverage {selectedBattery.coverageTier} · readiness {Math.round(selectedBattery.readiness)}%</span>
            </div>
            <button type="button" onClick={removeSelectedBattery}>Recall</button>
          </section>
        ) : (
          <section className="live-card" aria-label="Live simulation status">
            <Zap size={22} />
            <div>
              <strong>{placementKind ? "Click map to place ППО" : "Live Defense Active"}</strong>
              <span>Targets move continuously. ППО auto-engages inside abstract coverage.</span>
            </div>
          </section>
        )}
        <div className="live-stats" aria-label="Live defense telemetry">
          <span><strong>{game.liveThreats.length}</strong> Threats</span>
          <span><strong>{game.interceptions}</strong> Interceptions</span>
          <span><strong>{game.impacts}</strong> Impacts</span>
          <span><strong>{Math.round(game.wavePressure)}</strong> Pressure</span>
        </div>
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
            <span>This clears live threats, placements, and current resource state for this mode.</span>
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
