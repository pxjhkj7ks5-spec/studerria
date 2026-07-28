import { CalendarDays, Coins, Landmark, Users } from "lucide-react";
import { formatClock } from "../game/liveSimulation";
import type { GameState } from "../types/game";
import type { OperationPhase } from "../domain/contracts";
import { getCampaignMission } from "../data/campaignPlan";
import type { ReactNode } from "react";

interface ResourceBarProps {
  game: GameState;
  operationPhase: OperationPhase;
  mobile?: boolean;
}

export function ResourceBar({ game, operationPhase, mobile = false }: ResourceBarProps) {
  const campaignMission = game.campaign ? getCampaignMission(game.campaign.missionIndex) : null;
  const campaignElapsed = Math.max(0, game.elapsedMs - game.cycleStartedAtMs);
  const elapsedTime = `${String(Math.floor(campaignElapsed / 60_000)).padStart(2, "0")}:${String(Math.floor(campaignElapsed / 1_000) % 60).padStart(2, "0")}`;
  const campaignTime: ReactNode = campaignMission
    ? <span className="resource-time"><b>{elapsedTime}</b><i>{campaignMission.durationMinutes}:00</i></span>
    : formatClock(game.elapsedMs);
  const depot = game.campaign?.depot;
  const depotRate = depot ? depot.repairRemainingMs > 0 || depot.health <= 0 ? 0 : depot.health <= 50 ? 1 : 2 : 0;
  const depotDelta = depot?.repairRemainingMs
    ? `HP ${Math.round(depot.health)}% · ремонт ${Math.ceil(depot.repairRemainingMs / 1000)} с`
    : depotRate > 0
      ? `HP ${Math.round(depot!.health)}% · +${depotRate}/хв · ${Math.ceil((60_000 - depot!.productionProgressMs) / 1000)} с`
      : `HP ${Math.round(depot?.health || 0)}% · виробництво зупинено`;
  const items = [
    { label: "Бюджет", value: Math.round(game.resources.budget), icon: Coins, delta: "постачання" },
    { label: game.campaign ? "Склад БК" : "БК", value: game.campaign ? Math.round(depot?.stock || 0) : Math.round(game.resources.ammo), icon: Landmark, delta: game.campaign ? depotDelta : "запас" },
    { label: game.campaign ? "Стійкість" : "Мораль", value: `${Math.round(game.campaign?.civilianResilience ?? game.resources.morale)}%`, icon: Users, delta: "цивільні" },
    { label: game.campaign ? `Місія ${game.campaign.missionIndex}/5` : "Час", value: campaignTime, icon: CalendarDays, delta: operationPhase === "paused" ? "пауза" : "реальний час", className: "resource-card--mission-time" },
  ];

  return (
    <div className={`resource-bar ${mobile ? "resource-bar--mobile" : ""}`}>
      {items.map((item) => {
        const Icon = item.icon;
        return (
          <article className={`resource-card ${item.className || ""}`} key={item.label}>
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
