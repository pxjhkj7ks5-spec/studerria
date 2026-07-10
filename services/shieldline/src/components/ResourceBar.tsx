import { CalendarDays, Coins, Landmark, Users, Zap } from "lucide-react";
import { formatClock } from "../game/liveSimulation";
import type { GameState } from "../types/game";
import type { OperationPhase, SimulationSpeed } from "../domain/contracts";

interface ResourceBarProps {
  game: GameState;
  simulationSpeed: SimulationSpeed;
  operationPhase: OperationPhase;
  mobile?: boolean;
}

export function ResourceBar({ game, simulationSpeed, operationPhase, mobile = false }: ResourceBarProps) {
  const items = [
    { label: "Бюджет", value: Math.round(game.resources.budget), icon: Coins, delta: "постачання" },
    { label: "БК", value: Math.round(game.resources.ammo), icon: Landmark, delta: "запас" },
    { label: "Енергія", value: `${Math.round(game.resources.energy)}%`, icon: Zap, delta: "стабільність" },
    { label: "Мораль", value: `${Math.round(game.resources.morale)}%`, icon: Users, delta: "цивільні" },
    { label: "Політичний ресурс", value: Math.round(game.resources.political), icon: Landmark, delta: "капітал" },
    { label: "Час", value: formatClock(game.elapsedMs), icon: CalendarDays, delta: operationPhase === "paused" ? "пауза" : `x${simulationSpeed}` },
  ];

  return (
    <div className={`resource-bar ${mobile ? "resource-bar--mobile" : ""}`}>
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
