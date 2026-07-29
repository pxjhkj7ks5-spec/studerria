import { campaignMissions } from "../data/missions";
import type { MissionRun } from "../domain/contracts";
import type { CampaignMissionResult, GameState } from "../types/game";
import { unlockedCampaignMissionIndex } from "./campaignMeta";

const THREAT_LABELS: Record<string, string> = {
  Ballistic: "Балістика",
  Cruise: "Крилаті ракети",
  Decoy: "Приманки",
  Gerbera: "Gerbera",
  Jammer: "РЕП",
  "Low-signature cruise": "Малопомітні ракети",
  Recon: "Розвідники",
  Shahed: "Shahed",
};

export function localizeThreatClass(value: string) {
  return THREAT_LABELS[value] || value;
}

export function minimumCityHealth(game: Pick<GameState, "cities">) {
  if (!game.cities.length) return 100;
  return Math.max(0, Math.round(Math.min(...game.cities.map((city) => 100 - city.damage))));
}

export function buildCampaignCatalogPresentation(game: GameState) {
  const { campaign } = game;
  const completedIndexes = new Set(campaign?.previousMissionResults.map((result) => result.missionIndex) || []);
  const currentIndex = campaign?.completed ? 5 : unlockedCampaignMissionIndex(campaign);
  const mission = campaignMissions[currentIndex - 1] || campaignMissions[0];
  const completedCount = campaign?.completed ? campaignMissions.length : completedIndexes.size;

  return {
    mission,
    currentIndex,
    completedCount,
    progressPercent: Math.round((completedCount / campaignMissions.length) * 100),
    wallet: campaign?.campaignWallet || 0,
    depotStock: Math.round(campaign?.depot.stock ?? 10),
    minimumCityHp: campaign ? minimumCityHealth(game) : 100,
    ctaLabel: campaign?.completed ? "Кампанію завершено" : campaign ? "Продовжити кампанію" : "Почати кампанію",
    completed: Boolean(campaign?.completed),
    timeline: campaignMissions.map((item, index) => {
      const missionIndex = index + 1;
      const state = completedIndexes.has(missionIndex) || campaign?.completed
        ? "completed"
        : missionIndex === currentIndex
          ? "current"
          : "locked";
      return { mission: item, missionIndex, state } as const;
    }),
  };
}

export interface AfterActionPresentation {
  campaignResult: CampaignMissionResult | null;
  outcome: "victory" | "defeat" | "contained";
  outcomeLabel: string;
  title: string;
  objectiveSummary: string;
  interceptions: number;
  totalTargets: number;
  impacts: number;
  minimumCityHp: number;
  depotHealth: number | null;
  depotStock: number | null;
  economy: Array<{ label: string; value: number; tone?: "positive" | "negative" }>;
  finalWallet: number | null;
}

export function buildAfterActionPresentation(game: GameState, authoritativeRun?: MissionRun | null): AfterActionPresentation {
  const campaignResult = game.campaign?.lastAttemptResult || game.campaign?.previousMissionResults.at(-1) || null;
  const report = game.afterActionReports[0];
  const outcome = campaignResult?.outcome
    || (authoritativeRun?.result === "setback" ? "defeat" : authoritativeRun?.result)
    || (game.status === "won" ? "victory" : game.status === "lost" ? "defeat" : "contained");
  const mission = campaignResult ? campaignMissions[campaignResult.missionIndex - 1] : null;
  const interceptions = campaignResult?.interceptions ?? authoritativeRun?.interceptions ?? report?.defensePerformance.interceptions ?? game.interceptions;
  const impacts = campaignResult?.impacts ?? authoritativeRun?.impacts ?? report?.defensePerformance.missedThreats ?? game.impacts;
  const totalTargets = campaignResult?.totalTargets ?? interceptions + impacts;

  return {
    campaignResult,
    outcome,
    outcomeLabel: outcome === "victory" ? "Перемога" : outcome === "defeat" ? "Поразка" : "Атаку локалізовано",
    title: campaignResult?.title || mission?.title || "Післяопераційний звіт",
    objectiveSummary: campaignResult?.objectiveSummary || report?.situationSummary || (outcome === "victory" ? "Оборона виконала поставлене завдання." : outcome === "defeat" ? "Критичний об’єкт оборони втрачено." : "Основний тиск атаки локалізовано."),
    interceptions,
    totalTargets,
    impacts,
    minimumCityHp: campaignResult?.minimumCityHp ?? minimumCityHealth(game),
    depotHealth: campaignResult?.depotHealth ?? game.campaign?.depot.health ?? null,
    depotStock: campaignResult?.depotStock ?? game.campaign?.depot.stock ?? null,
    economy: campaignResult ? [
      { label: "Стартовий грант", value: campaignResult.missionGrant, tone: "positive" },
      { label: "Заробіток за цілі", value: campaignResult.killReward, tone: "positive" },
      { label: "Бонуси", value: campaignResult.bonusRewards, tone: "positive" },
      { label: "Штрафи й витрати", value: -Math.abs(campaignResult.penaltyCosts), tone: campaignResult.penaltyCosts ? "negative" : undefined },
    ] : [],
    finalWallet: campaignResult?.walletAfterMission ?? null,
  };
}
