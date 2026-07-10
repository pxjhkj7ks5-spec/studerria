import { RadioTower, ShieldCheck, Siren, Zap } from "lucide-react";
import type { MapMode } from "../types/game";

interface MapLegendProps {
  mode: MapMode;
  embedded?: boolean;
}

const modeCopy: Record<MapMode, string> = {
  live: "Міста, сектори, радарні контакти та активні перехоплення.",
  threats: "Орієнтовні коридори руху та стан радарних контактів.",
  coverage: "Зони прикриття ППО та стан готовності установок.",
  logistics: "Постачання, готовність міст, затримки маршрутів і ремонти.",
};

export function MapLegend({ mode, embedded = false }: MapLegendProps) {
  return (
    <aside className={`map-legend ${embedded ? "map-legend--embedded" : ""}`} aria-label="Умовні позначення">
      <div className="legend-heading">
        <strong>Умовні позначення</strong>
        <span>{modeCopy[mode]}</span>
      </div>
      <div className="legend-grid">
        <LegendItem icon={RadioTower} tone="uncertain" label="Радарний контакт" />
        <LegendItem icon={Siren} tone="confirmed" label="Підтверджена ціль" />
        <LegendItem icon={ShieldCheck} tone="intercepted" label="Перехоплено" />
        <LegendItem icon={Zap} tone="impact" label="Влучання" />
      </div>
    </aside>
  );
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
