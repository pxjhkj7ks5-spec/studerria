import type { CampaignMode, Resources } from "../types/game";

export interface CampaignModeDefinition {
  id: CampaignMode;
  title: string;
  durationLabel: string;
  description: string;
  posture: string;
  resources: Resources;
}

export const campaignModes: CampaignModeDefinition[] = [
  {
    id: "training",
    title: "Training",
    durationLabel: "Guided",
    description: "Lower pressure, higher reserves, and slower escalation for learning placement and coverage.",
    posture: "Low pressure",
    resources: { budget: 160, ammo: 120, energy: 86, morale: 82, political: 60 },
  },
  {
    id: "seven-day",
    title: "7-Day Campaign",
    durationLabel: "1 week",
    description: "A compact crisis with enough scarcity to force tradeoffs without a long commitment.",
    posture: "Balanced pressure",
    resources: { budget: 130, ammo: 94, energy: 80, morale: 75, political: 48 },
  },
  {
    id: "crisis",
    title: "30-Day Crisis",
    durationLabel: "Extended",
    description: "A longer campaign where readiness, logistics, morale, and city service attrition matter.",
    posture: "Sustained pressure",
    resources: { budget: 120, ammo: 86, energy: 78, morale: 72, political: 45 },
  },
  {
    id: "sandbox",
    title: "Sandbox",
    durationLabel: "Open",
    description: "Extra resources and no strict pacing expectation for experimenting with layouts.",
    posture: "Open simulation",
    resources: { budget: 240, ammo: 180, energy: 92, morale: 88, political: 80 },
  },
];

export function getCampaignModeDefinition(mode: CampaignMode) {
  return campaignModes.find((item) => item.id === mode) || campaignModes[2];
}
