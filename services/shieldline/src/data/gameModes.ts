import type { GameModeId } from "../domain/contracts";

export interface GameModeDefinition {
  id: GameModeId;
  title: string;
  eyebrow: string;
  description: string;
  duration: string;
  difficulty: string;
  resources: string;
  mainRisk: string;
  victory: string;
  availability: "available" | "preview";
}

export const gameModes: GameModeDefinition[] = [
  {
    id: "campaign", eyebrow: "Core operation", title: "Campaign", duration: "30-120 min · x8", difficulty: "Adaptive", resources: "Ammo · morale · reserves",
    description: "A sequence of night operations. Each mission preserves the city state and sharpens the next decision.", mainRisk: "Cascading pressure across sectors", victory: "Protect critical city systems through the operation", availability: "available",
  },
  {
    id: "daily-defense", eyebrow: "Daily city", title: "Daily Defense", duration: "2-8 min", difficulty: "Daily adaptive", resources: "Repair · supply · readiness",
    description: "One persistent city, one resolved night. Review the report, adjust its sectors, then prepare tomorrow.", mainRisk: "Slow infrastructure attrition", victory: "Keep morale and essential systems stable", availability: "preview",
  },
  {
    id: "ranked-challenge", eyebrow: "Shared seed", title: "Ranked Challenge", duration: "8-15 min", difficulty: "Fixed scenario", resources: "Equal loadout", description: "Everyone receives the same daily or weekly scenario. Score comes from outcomes, not purchases.", mainRisk: "No room for brute force", victory: "Earn the best score from the same seed", availability: "preview",
  },
  {
    id: "co-op-command", eyebrow: "1-5 players", title: "Co-op Command", duration: "Async / live later", difficulty: "Team adaptive", resources: "Sectors · HQ reserve", description: "North, South, East, West and HQ share one city. Async command logs come first; live command is a future layer.", mainRisk: "Conflicting priorities", victory: "Resolve the night as a coordinated command", availability: "preview",
  },
  {
    id: "sandbox", eyebrow: "No ranking", title: "Sandbox", duration: "Open-ended", difficulty: "Player set", resources: "Unlimited test reserve", description: "Test sector layouts and doctrines with no progression or leaderboard impact.", mainRisk: "None", victory: "Learn the tools and validate a plan", availability: "preview",
  },
  {
    id: "training", eyebrow: "Guided", title: "Training", duration: "10 min", difficulty: "Guided", resources: "Protected reserve", description: "A short guided operation that explains sectors, readiness, reports and replay without punishment.", mainRisk: "Low", victory: "Complete the command checklist", availability: "preview",
  },
];

export function getGameMode(id: GameModeId) {
  return gameModes.find((mode) => mode.id === id) || gameModes[0];
}
