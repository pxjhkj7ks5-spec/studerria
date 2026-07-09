import type { MissionDefinition } from "../domain/contracts";

export const campaignMissions: MissionDefinition[] = [
  {
    id: "campaign-night-01", modeId: "campaign", title: "Night 01: Signal Window", subtitle: "Campaign · Mission 1 of 3", durationMinutes: 45, simulationSpeed: 8, difficulty: "standard",
    resources: { budget: 120, ammo: 82, morale: 76, energy: 78 }, mainRisk: "East sector saturation", victoryCondition: "Contain at least two waves and keep city morale above 55%.",
    briefing: "Intermittent tracks are building along the eastern corridor. Keep the reserve flexible: certainty will arrive late, but the window to react is short.",
    waves: [
      { id: "wave-01", index: 1, threatKind: "geran2", originSector: "east", targetSector: "east", etaSeconds: 28, size: 8, difficulty: 42 },
      { id: "wave-02", index: 2, threatKind: "kh101", originSector: "north", targetSector: "north", etaSeconds: 52, size: 3, difficulty: 62 },
      { id: "wave-03", index: 3, threatKind: "gerbera", originSector: "south", targetSector: "west", etaSeconds: 75, size: 6, difficulty: 48 },
    ],
  },
];
