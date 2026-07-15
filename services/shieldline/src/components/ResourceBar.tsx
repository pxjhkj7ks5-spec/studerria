import { CalendarDays, Coins, Landmark, Users } from "lucide-react";
import { formatClock } from "../game/liveSimulation";
import type { GameState } from "../types/game";
import type { OperationPhase } from "../domain/contracts";
import { getCampaignMission } from "../data/campaignPlan";

interface ResourceBarProps {
  game: GameState;
  operationPhase: OperationPhase;
  mobile?: boolean;
}

export function ResourceBar({ game, operationPhase, mobile = false }: ResourceBarProps) {
  const campaignMission = game.campaign ? getCampaignMission(game.campaign.missionIndex) : null;
  const campaignElapsed = Math.max(0, game.elapsedMs - game.cycleStartedAtMs);
  const campaignTime = campaignMission
    ? `${String(Math.floor(campaignElapsed / 60_000)).padStart(2, "0")}:${String(Math.floor(campaignElapsed / 1_000) % 60).padStart(2, "0")} / ${campaignMission.durationMinutes}:00`
    : formatClock(game.elapsedMs);
  const finiteBatteries = game.batteries.filter((battery) => typeof battery.currentAmmo === "number").map((battery) => ({ battery, capacity: getCampaignAmmoCapacity(battery.kind) }));
  const campaignAmmoPercent = finiteBatteries.length ? Math.round(finiteBatteries.reduce((sum, entry) => sum + Number(entry.battery.currentAmmo), 0) / Math.max(1, finiteBatteries.reduce((sum, entry) => sum + entry.capacity, 0)) * 100) : 0;
  const items = [
    { label: "Бюджет", value: Math.round(game.resources.budget), icon: Coins, delta: "постачання" },
    { label: game.campaign ? "БК мережі" : "БК", value: game.campaign ? `${campaignAmmoPercent}%` : Math.round(game.resources.ammo), icon: Landmark, delta: "запас" },
    { label: game.campaign ? "Стійкість" : "Мораль", value: `${Math.round(game.campaign?.civilianResilience ?? game.resources.morale)}%`, icon: Users, delta: "цивільні" },
    { label: game.campaign ? `Місія ${game.campaign.missionIndex}/5` : "Час", value: campaignTime, icon: CalendarDays, delta: operationPhase === "paused" ? "пауза" : "реальний час" },
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

function getCampaignAmmoCapacity(kind: GameState["batteries"][number]["kind"]) {
  const capacities: Partial<Record<typeof kind, number>> = { radar: 0, mvg: 5, boat: 6, ew: 0, manpads: 3, gepard: 8, buk: 4, s300: 4, "iris-t": 4, nasams: 6, patriot: 2, "drone-operators": 6 };
  return capacities[kind] || 0;
}
