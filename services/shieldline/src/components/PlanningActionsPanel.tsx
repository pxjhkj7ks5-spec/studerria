import { BatteryCharging, Bell, Brain, Gauge, HandCoins, HeartPulse, Route } from "lucide-react";
import { planningActionDefinitions } from "../game/planningActions";
import { useGameStore } from "../store/useGameStore";
import type { PlanningActionId } from "../types/game";

const actionIcons: Record<PlanningActionId, typeof Bell> = {
  "high-alert": Bell,
  "conserve-ammo": Gauge,
  "emergency-aid": HandCoins,
  "energy-repair": BatteryCharging,
  "morale-campaign": HeartPulse,
  "rapid-redeployment": Route,
  "intelligence-focus": Brain,
};

export function PlanningActionsPanel() {
  const game = useGameStore((state) => state.game);
  const toggleAction = useGameStore((state) => state.togglePlanningAction);
  const planning = game.cyclePhase === "planning";

  return (
    <section className="planning-card" aria-label="Planning phase actions">
      <div className="planning-heading">
        <strong>Planning Phase</strong>
        <span>{planning ? `${game.planningActions.selected.length}/2 actions selected` : "Locked during attack cycle"}</span>
      </div>
      <div className="planning-actions">
        {planningActionDefinitions.map((action) => {
          const selected = game.planningActions.selected.includes(action.id);
          const cooldown = game.planningActions.cooldowns[action.id] || 0;
          const Icon = actionIcons[action.id];
          const disabled = !planning || (!selected && game.planningActions.selected.length >= 2) || cooldown > 0;
          return (
            <button
              className={`planning-action ${selected ? "planning-action--selected" : ""}`}
              type="button"
              key={action.id}
              onClick={() => toggleAction(action.id)}
              disabled={disabled}
              title={action.description}
            >
              <Icon size={15} />
              <span>{action.title}</span>
              <small>{cooldown > 0 ? `CD ${cooldown}` : costLabel(action.cost)}</small>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function costLabel(cost: Record<string, number | undefined>) {
  const entries = Object.entries(cost).filter(([, value]) => value);
  if (!entries.length) return "No cost";
  return entries.map(([key, value]) => `${key.slice(0, 3)} ${value}`).join(" · ");
}
