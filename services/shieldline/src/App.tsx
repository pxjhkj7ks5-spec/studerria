import { Activity, Menu, RotateCcw, Shield } from "lucide-react";
import { CityPanel } from "./components/CityPanel";
import { IntelLog } from "./components/IntelLog";
import { ResourceBar } from "./components/ResourceBar";
import { TacticalMap } from "./components/TacticalMap";
import { UnitRail } from "./components/UnitRail";
import { useGameStore } from "./store/useGameStore";

export default function App() {
  const game = useGameStore((state) => state.game);
  const resetCampaign = useGameStore((state) => state.resetCampaign);
  const nextDay = useGameStore((state) => state.nextDay);
  const selectedCityId = useGameStore((state) => state.selectedCityId);
  const selectedCity = game.cities.find((city) => city.id === selectedCityId) || game.cities[0];
  const disabled = game.status !== "active";

  return (
    <main className="shell" aria-label="Shieldline strategy simulation">
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
            <span>Studerria</span>
          </div>
        </div>
        <ResourceBar game={game} />
      </header>

      <section className="map-stage" aria-label="Campaign map">
        <TacticalMap />
        <aside className="left-rail" aria-label="Map layers">
          <button className="nav-pill nav-pill--active" type="button">Overview</button>
          <button className="nav-pill" type="button">Intel</button>
          <button className="nav-pill" type="button">Resources</button>
          <button className="nav-pill" type="button">Settings</button>
        </aside>
        <CityPanel city={selectedCity} game={game} />
      </section>

      <aside className="right-panel" aria-label="Intelligence and event log">
        <IntelLog game={game} />
        {game.status !== "active" ? (
          <div className={`status-card status-card--${game.status}`}>
            <Activity size={22} />
            <div>
              <strong>{game.status === "won" ? "Campaign Survived" : "Campaign Failed"}</strong>
              <span>{game.statusReason}</span>
            </div>
          </div>
        ) : null}
        <button className="next-day" type="button" onClick={nextDay} disabled={disabled}>
          <span>Next Day</span>
          <span aria-hidden="true">›</span>
        </button>
        <button className="reset-button" type="button" onClick={resetCampaign}>
          <RotateCcw size={16} />
          Reset Campaign
        </button>
      </aside>

      <footer className="unit-dock" aria-label="Defense unit cards">
        <UnitRail />
      </footer>
    </main>
  );
}
