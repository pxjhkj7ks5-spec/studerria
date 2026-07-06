import { Factory, Radio, ShieldAlert, Truck, Users, Wrench, Zap } from "lucide-react";
import type { City, GameState } from "../types/game";

interface CityPanelProps {
  city: City;
  game: GameState;
}

export function CityPanel({ city, game }: CityPanelProps) {
  const cityUnits = game.batteries.filter((unit) => unit.assignedCityId === city.id);
  const cityNodes = game.infrastructure.filter((node) => node.cityId === city.id);
  const communications = averageKind(cityNodes, "communications", city.infrastructure);
  const logistics = averageKind(cityNodes, "logistics", city.infrastructure);
  const supplyStatus = game.logistics.citySupply[city.id] || "strained";
  const repairCapacity = Math.max(12, Math.round((city.infrastructure + logistics - city.damage) / 2));
  const risk = city.damage > 55 ? "Critical" : city.energy < 45 || city.infrastructure < 50 ? "Stressed" : "Stable";
  const alertState = city.alertState || "calm";
  const alertLabel = alertState === "air-raid" ? "Air raid" : alertState === "probable-target" ? "Probable target" : "Calm";

  return (
    <section className="city-panel" aria-label={`${city.name} status`}>
      <div className="panel-heading">
        <span>Selected City</span>
        <strong>{city.name}</strong>
      </div>
      <div className={`city-posture city-posture--${risk.toLowerCase()}`}>
        <ShieldAlert size={17} />
        <span>{risk} posture</span>
        <strong>{cityUnits.length} PPO nearby</strong>
      </div>
      <div className={`city-alert-state city-alert-state--${alertState}`}>
        <span>{alertLabel}</span>
        <strong>{alertState === "calm" ? "No active track nearby" : "Command alert active"}</strong>
      </div>
      <div className="city-systems">
        <Metric icon={Factory} label="City services" value={city.infrastructure} />
        <Metric icon={Zap} label="Energy" value={city.energy} />
        <Metric icon={Radio} label="Comms" value={communications} />
        <Metric icon={Truck} label={`Logistics (${supplyStatus.replace("-", " ")})`} value={logistics} />
        <Metric icon={Users} label="Civil morale" value={city.morale} />
        <Metric icon={Wrench} label="Repair cap" value={repairCapacity} />
      </div>
      <div className="assigned-row">
        <span>{cityUnits.length} defense units nearby</span>
        <small>abstract supply: {supplyStatus.replace("-", " ")}</small>
      </div>
    </section>
  );
}

function averageKind(nodes: GameState["infrastructure"], kind: GameState["infrastructure"][number]["kind"], fallback: number) {
  const matching = nodes.filter((node) => node.kind === kind);
  if (!matching.length) return fallback;
  return matching.reduce((sum, node) => sum + node.integrity, 0) / matching.length;
}

interface MetricProps {
  icon: typeof Factory;
  label: string;
  value: number;
}

function Metric({ icon: Icon, label, value }: MetricProps) {
  const rounded = Math.round(value);
  const tone = rounded < 40 ? "danger" : rounded < 65 ? "warning" : "stable";
  return (
    <div className={`city-metric city-metric--${tone}`}>
      <Icon size={15} />
      <span>{label}</span>
      <strong>{rounded}%</strong>
      <i style={{ width: `${Math.max(4, Math.min(100, rounded))}%` }} />
    </div>
  );
}
