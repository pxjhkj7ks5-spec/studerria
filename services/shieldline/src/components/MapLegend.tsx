import { CircleDot, RadioTower, ShieldCheck, Siren, Zap } from "lucide-react";
import type { MapMode } from "../types/game";

interface MapLegendProps {
  mode: MapMode;
}

const modeCopy: Record<MapMode, string> = {
  live: "Live tracks, cities, sectors, and active engagements.",
  threats: "Approximate corridors and confidence state. No real routing data.",
  coverage: "Abstract ППО coverage tiers and readiness pulses.",
  logistics: "Supply pressure, damaged nodes, and repair priorities.",
};

export function MapLegend({ mode }: MapLegendProps) {
  return (
    <aside className="map-legend" aria-label="Map legend">
      <div className="legend-heading">
        <strong>{mode.toUpperCase()} LAYER</strong>
        <span>{modeCopy[mode]}</span>
      </div>
      <div className="legend-grid">
        <LegendItem icon={CircleDot} tone="uncertain" label="Uncertain" />
        <LegendItem icon={RadioTower} tone="detected" label="Detected" />
        <LegendItem icon={Siren} tone="confirmed" label="Confirmed" />
        <LegendItem icon={ShieldCheck} tone="intercepted" label="Intercepted" />
        <LegendItem icon={Zap} tone="impact" label="Impact" />
      </div>
    </aside>
  );
}

interface LegendItemProps {
  icon: typeof CircleDot;
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
