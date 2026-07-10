import { CalendarDays, Coins, Landmark, Users, Zap } from "lucide-react";
import { formatClock } from "../game/liveSimulation";
import type { GameState } from "../types/game";
import type { OperationPhase, SimulationSpeed } from "../domain/contracts";

interface ResourceBarProps {
  game: GameState;
  simulationSpeed: SimulationSpeed;
  operationPhase: OperationPhase;
}

export function ResourceBar({ game, simulationSpeed, operationPhase }: ResourceBarProps) {
  const items = [
    { label: "Budget", value: Math.round(game.resources.budget), icon: Coins, delta: "+ supply" },
    { label: "Ammo", value: Math.round(game.resources.ammo), icon: Landmark, delta: "+ trickle" },
    { label: "Energy", value: `${Math.round(game.resources.energy)}%`, icon: Zap, delta: "stability" },
    { label: "Morale", value: `${Math.round(game.resources.morale)}%`, icon: Users, delta: "civil" },
    { label: "Political", value: Math.round(game.resources.political), icon: Landmark, delta: "capital" },
    { label: "Live", value: formatClock(game.elapsedMs), icon: CalendarDays, delta: operationPhase === "paused" ? "paused" : `x${simulationSpeed}` },
  ];

  return (
    <div className="resource-bar">
      {items.map((item) => {
        const Icon = item.icon;
        return (
          <article className="resource-card" key={item.label}>
            <Icon className="resource-icon" size={24} />
            <div>
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
            <small>{item.delta}</small>
          </article>
        );
      })}
    </div>
  );
}
