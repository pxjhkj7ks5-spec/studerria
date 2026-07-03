import { Factory, Radio, ShieldAlert, Zap } from "lucide-react";
import type { City, GameState } from "../types/game";

interface CityPanelProps {
  city: City;
  game: GameState;
}

export function CityPanel({ city, game }: CityPanelProps) {
  const cityUnits = game.units.filter((unit) => unit.cityId === city.id);
  const nodeCount = game.infrastructure.filter((node) => node.cityId === city.id).length;

  return (
    <section className="city-panel" aria-label={`${city.name} status`}>
      <div className="panel-heading">
        <span>Selected City</span>
        <strong>{city.name}</strong>
      </div>
      <div className="city-grid">
        <Metric icon={Factory} label="Infra" value={city.infrastructure} />
        <Metric icon={Zap} label="Energy" value={city.energy} />
        <Metric icon={ShieldAlert} label="Damage" value={city.damage} invert />
        <Metric icon={Radio} label="Nodes" value={nodeCount} raw />
      </div>
      <div className="assigned-row">
        <span>{cityUnits.length} units assigned</span>
        <small>click unit below, then redeploy here</small>
      </div>
    </section>
  );
}

interface MetricProps {
  icon: typeof Factory;
  label: string;
  value: number;
  raw?: boolean;
  invert?: boolean;
}

function Metric({ icon: Icon, label, value, raw = false, invert = false }: MetricProps) {
  const level = invert ? 100 - value : value;
  return (
    <div className="city-metric">
      <Icon size={16} />
      <span>{label}</span>
      <strong>{raw ? value : `${Math.round(value)}%`}</strong>
      {!raw ? <i style={{ width: `${Math.max(4, Math.min(100, level))}%` }} /> : null}
    </div>
  );
}
