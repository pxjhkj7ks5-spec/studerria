import { useEffect, useRef } from "react";
import { Activity, AlertTriangle, Crosshair, Menu, RotateCcw, Shield, Zap } from "lucide-react";
import { CityPanel } from "./components/CityPanel";
import { IntelLog } from "./components/IntelLog";
import { ResourceBar } from "./components/ResourceBar";
import { TacticalMap } from "./components/TacticalMap";
import { UnitRail } from "./components/UnitRail";
import { useGameStore } from "./store/useGameStore";

export default function App() {
  const game = useGameStore((state) => state.game);
  const resetCampaign = useGameStore((state) => state.resetCampaign);
  const tick = useGameStore((state) => state.tick);
  const removeSelectedBattery = useGameStore((state) => state.removeSelectedBattery);
  const selectedCityId = useGameStore((state) => state.selectedCityId);
  const selectedBatteryId = useGameStore((state) => state.selectedBatteryId);
  const placementKind = useGameStore((state) => state.placementKind);
  const selectedCity = game.cities.find((city) => city.id === selectedCityId) || game.cities[0];
  const selectedBattery = game.batteries.find((battery) => battery.id === selectedBatteryId) || null;
  const lastTickRef = useRef<number | null>(null);
  const accumulatorRef = useRef(0);

  useEffect(() => {
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
  }, [tick]);

  return (
    <main className="shell" aria-label="Shieldline real-time defense simulation">
      <header className="topbar">
        <div className="brand-card">
          <button className="icon-button" type="button" aria-label="Shieldline menu">
            <Menu size={24} />
          </button>
          <div className="brand-mark" aria-hidden="true">
            <Shield size={28} />
          </div>
          <div>
            <h1>Shieldline</h1>
            <span>Live defense</span>
          </div>
        </div>
        <ResourceBar game={game} />
      </header>

      <section className={`map-stage ${placementKind ? "map-stage--placing" : ""}`} aria-label="Live defense map">
        <TacticalMap />
        <aside className="left-rail" aria-label="Map layers">
          <button className="nav-pill nav-pill--active" type="button">Live</button>
          <button className="nav-pill" type="button">Threats</button>
          <button className="nav-pill" type="button">Coverage</button>
          <button className="nav-pill" type="button">Logistics</button>
        </aside>
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
              <span>Coverage {selectedBattery.coverageTier} - readiness {Math.round(selectedBattery.readiness)}%</span>
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
        {game.resources.ammo < 15 ? (
          <div className="status-card status-card--lost">
            <AlertTriangle size={20} />
            <div>
              <strong>Ammo Low</strong>
              <span>Coverage remains active, but engagements are limited.</span>
            </div>
          </div>
        ) : null}
        <button className="reset-button" type="button" onClick={resetCampaign}>
          <RotateCcw size={16} />
          Reset Campaign
        </button>
      </aside>

      <footer className="unit-dock" aria-label="Defense placement cards">
        <UnitRail />
      </footer>
    </main>
  );
}
