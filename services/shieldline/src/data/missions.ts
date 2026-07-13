import type { MissionDefinition } from "../domain/contracts";
import { CAMPAIGN_RANDOM_LAUNCH_SECTOR_IDS } from "../game/launchSystem.mjs";

export const campaignMissions: MissionDefinition[] = [
  {
    id: "campaign-night-01", modeId: "campaign", title: "Random Threat Night", subtitle: "Campaign · Single mission", durationMinutes: 10, difficulty: "standard",
    resources: { budget: 120, ammo: 82, morale: 76, energy: 78 }, mainRisk: "Unpredictable mixed launches", victoryCondition: "Contain the randomly generated air attack.",
    briefing: "Every operation generates a new mix of launch points, airborne threats and defended directions.",
    launchSectorIds: [...CAMPAIGN_RANDOM_LAUNCH_SECTOR_IDS],
    randomWaveCount: 6,
    waves: [],
  },
];
