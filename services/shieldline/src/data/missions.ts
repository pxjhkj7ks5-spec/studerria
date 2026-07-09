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
  {
    id: "campaign-night-02", modeId: "campaign", title: "Night 02: Blackout Relay", subtitle: "Campaign · Mission 2 of 3", durationMinutes: 60, simulationSpeed: 8, difficulty: "hard",
    resources: { budget: 118, ammo: 76, morale: 72, energy: 69 }, mainRisk: "Southern decoys masking a grid strike", victoryCondition: "Hold energy above 55% and contain two critical waves.",
    briefing: "A rolling blackout masks a mixed southern approach. Preserve radar coverage long enough to separate decoys from the relay strike.",
    waves: [
      { id: "wave-01", index: 1, threatKind: "geran2", originSector: "south", targetSector: "south", etaSeconds: 24, size: 10, difficulty: 48 },
      { id: "wave-02", index: 2, threatKind: "kalibr", originSector: "east", targetSector: "east", etaSeconds: 50, size: 5, difficulty: 67 },
      { id: "wave-03", index: 3, threatKind: "kh101", originSector: "north", targetSector: "east", etaSeconds: 79, size: 4, difficulty: 72 },
    ],
  },
  {
    id: "campaign-night-03", modeId: "campaign", title: "Night 03: Last Reserve", subtitle: "Campaign · Mission 3 of 3", durationMinutes: 90, simulationSpeed: 8, difficulty: "expert",
    resources: { budget: 112, ammo: 68, morale: 66, energy: 62 }, mainRisk: "Multi-sector saturation", victoryCondition: "Protect the HQ and finish with morale above 45%.",
    briefing: "The final pressure wave is broad and fast. Allocate the reserve deliberately: a perfect sector defense is less valuable than a city that keeps functioning.",
    waves: [
      { id: "wave-01", index: 1, threatKind: "gerbera", originSector: "east", targetSector: "east", etaSeconds: 20, size: 12, difficulty: 58 },
      { id: "wave-02", index: 2, threatKind: "kalibr", originSector: "south", targetSector: "west", etaSeconds: 47, size: 6, difficulty: 78 },
      { id: "wave-03", index: 3, threatKind: "kh101", originSector: "north", targetSector: "north", etaSeconds: 74, size: 5, difficulty: 84 },
    ],
  },
];
