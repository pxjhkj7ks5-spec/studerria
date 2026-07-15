import { Activity, ChevronDown, RadioTower, ShieldCheck, Siren, Users, Zap } from "lucide-react";
import type { GameState, MapMode } from "../types/game";

interface MapLegendProps {
  mode: MapMode;
  game: GameState;
  embedded?: boolean;
}

const modeCopy: Record<MapMode, string> = {
  live: "Повітряна обстановка в реальному часі",
  threats: "Коридори руху та стан контактів",
  coverage: "Зони прикриття та готовність ППО",
  logistics: "Постачання, маршрути й ремонти",
};

function threatLevel(pressure: number) {
  if (pressure >= 75) return { label: "CRITICAL", tone: "critical" };
  if (pressure >= 50) return { label: "HIGH", tone: "high" };
  if (pressure >= 25) return { label: "ELEVATED", tone: "elevated" };
  return { label: "LOW", tone: "low" };
}

export function MapLegend({ mode, game, embedded = false }: MapLegendProps) {
  const activeContacts = game.liveThreats.filter((threat) => threat.revealed && (threat.status === "inbound" || threat.status === "engaged")).length;
  const confirmedTargets = game.liveThreats.filter((threat) => threat.revealed && threat.confidence >= 58 && (threat.status === "inbound" || threat.status === "engaged")).length;
  const safety = game.campaign?.civilianResilience ?? (game.cities.length ? Math.round(game.cities.reduce((sum, city) => sum + city.morale, 0) / game.cities.length) : 0);
  const level = threatLevel(game.wavePressure);

  return (
    <aside className={`map-legend intel-panel ${embedded ? "map-legend--embedded intel-panel--embedded" : ""}`} aria-label="Оперативна обстановка">
      <div className="intel-panel__heading">
        <span><Activity size={14} /> Оперативна обстановка</span>
        <b className={`threat-level threat-level--${level.tone}`}>{level.label}</b>
      </div>
      <span className="intel-panel__mode">{modeCopy[mode]}</span>
      <div className="intel-panel__metrics">
        <IntelMetric label="Контакти" value={activeContacts} tone="radar" />
        <IntelMetric label="Підтверджено" value={confirmedTargets} tone="confirmed" />
        <IntelMetric label="Перехоплення" value={game.engagementEvents.filter((event) => event.style !== "radar" && !event.resolved).length} tone="intercepted" />
        <IntelMetric label="Влучання" value={game.impacts} tone="impact" />
      </div>
      <div className="intel-panel__safety">
        <Users size={13} />
        <span>Цивільна стійкість</span>
        <b>{safety}%</b>
        <i><span style={{ width: `${Math.max(0, Math.min(100, safety))}%` }} /></i>
      </div>
      <details className="intel-panel__legend" open={embedded}>
        <summary>Умовні позначення <ChevronDown size={13} /></summary>
        <div className="legend-grid">
          <LegendItem icon={RadioTower} tone="uncertain" label="Радарний контакт" />
          <LegendItem icon={Siren} tone="confirmed" label="Підтверджена ціль" />
          <LegendItem icon={ShieldCheck} tone="intercepted" label="Перехоплено" />
          <LegendItem icon={Zap} tone="impact" label="Влучання" />
        </div>
      </details>
    </aside>
  );
}

function IntelMetric({ label, value, tone }: { label: string; value: number; tone: string }) {
  return <span className={`intel-metric intel-metric--${tone}`}><small>{label}</small><b>{value}</b></span>;
}

interface LegendItemProps {
  icon: typeof RadioTower;
  tone: string;
  label: string;
}

function LegendItem({ icon: Icon, tone, label }: LegendItemProps) {
  return (
    <span className={`legend-item legend-item--${tone}`}>
      <Icon size={14} />
      {label}
    </span>
  );
}
