import { CalendarDays, Coins, Landmark, Users, Zap } from "lucide-react";
import type { GameState } from "../types/game";

interface ResourceBarProps {
  game: GameState;
}

export function ResourceBar({ game }: ResourceBarProps) {
  const items = [
    { label: "Budget", value: Math.round(game.resources.budget), icon: Coins, delta: "+ supply" },
    { label: "Ammo", value: Math.round(game.resources.ammo), icon: Landmark, delta: "+ logistics" },
    { label: "Energy", value: `${Math.round(game.resources.energy)}%`, icon: Zap, delta: "stability" },
    { label: "Morale", value: `${Math.round(game.resources.morale)}%`, icon: Users, delta: "civil" },
    { label: "Political", value: Math.round(game.resources.political), icon: Landmark, delta: "capital" },
    { label: "Day", value: Math.min(game.day, 30), icon: CalendarDays, delta: "/ 30" },
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
