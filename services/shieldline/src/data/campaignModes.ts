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
    title: "Навчання",
    durationLabel: "Зі супроводом",
    description: "Нижчий тиск, більші резерви та повільніше наростання для навчання розміщенню й прикриттю.",
    posture: "Низький тиск",
    resources: { budget: 160, ammo: 120, energy: 86, morale: 82, political: 60 },
  },
  {
    id: "seven-day",
    title: "7-денна кампанія",
    durationLabel: "1 тиждень",
    description: "Коротка криза з обмеженими ресурсами та необхідністю ухвалювати компромісні рішення.",
    posture: "Збалансований тиск",
    resources: { budget: 130, ammo: 94, energy: 80, morale: 75, political: 48 },
  },
  {
    id: "crisis",
    title: "30-денна криза",
    durationLabel: "Тривала",
    description: "Тривала кампанія, де важливі готовність, логістика, мораль і стан міських служб.",
    posture: "Постійний тиск",
    resources: { budget: 120, ammo: 86, energy: 78, morale: 72, political: 45 },
  },
  {
    id: "sandbox",
    title: "Пісочниця",
    durationLabel: "Вільна",
    description: "Додаткові ресурси та вільний темп для експериментів із розміщенням.",
    posture: "Вільна симуляція",
    resources: { budget: 240, ammo: 180, energy: 92, morale: 88, political: 80 },
  },
];

export function getCampaignModeDefinition(mode: CampaignMode) {
  return campaignModes.find((item) => item.id === mode) || campaignModes[2];
}
