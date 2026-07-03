import { initialCities, initialInfrastructure } from "../data/mapData";
import { unitDefinitions } from "../data/units";
import type { DailyForecast, DeployedUnit, GameState, IntelEntry } from "../types/game";

const initialUnits: DeployedUnit[] = [
  { id: "seed-radar-kyiv", kind: "radar", cityId: "kyiv", readiness: 86 },
  { id: "seed-short-kyiv", kind: "short", cityId: "kyiv", readiness: 84 },
  { id: "seed-mobile-dnipro", kind: "mobile", cityId: "dnipro", readiness: 82 },
  { id: "seed-repair-lviv", kind: "repair", cityId: "lviv", readiness: 88 },
  { id: "seed-logistics-odesa", kind: "logistics", cityId: "odesa", readiness: 84 },
  { id: "seed-intel-kharkiv", kind: "intel", cityId: "kharkiv", readiness: 86 },
];

const openingLog: IntelEntry[] = [
  {
    id: "briefing-1",
    day: 1,
    title: "Intel Briefing",
    body: "Multiple disruptions are possible this week. Preserve energy, morale, and repair capacity.",
    tone: "info",
  },
  {
    id: "safety-1",
    day: 1,
    title: "Simulation Scope",
    body: "Shieldline uses fictional, abstract mechanics. It does not model real deployments or ranges.",
    tone: "info",
  },
];

export function createForecast(day: number, random: () => number): DailyForecast {
  const roll = random();
  const weather = roll > 0.84 ? "storm" : roll > 0.64 ? "poor" : "clear";
  const supportDelay = random() > 0.78;
  const pressure = Math.round(10 + random() * 25 + day * 0.7);
  const warningBank = [
    "Signals suggest a mixed pressure campaign, but target confidence is low.",
    "Analysts report unusual routing patterns near critical infrastructure.",
    "Support teams expect a difficult maintenance window.",
    "Several warnings appear contradictory. Keep reserves flexible.",
  ];

  return {
    day,
    weather,
    supportDelay,
    pressure,
    vagueWarning: warningBank[Math.floor(random() * warningBank.length)] || warningBank[0],
  };
}

export function createInitialState(random: () => number = Math.random): GameState {
  return {
    day: 1,
    status: "active",
    statusReason: "",
    resources: {
      budget: 120,
      ammo: 86,
      energy: 78,
      morale: 72,
      political: 45,
    },
    cities: initialCities.map((city) => ({ ...city })),
    infrastructure: initialInfrastructure.map((node) => ({ ...node })),
    units: initialUnits.map((unit) => ({ ...unit })),
    log: openingLog,
    forecast: createForecast(1, random),
  };
}

export function getUnitDefinition(kind: DeployedUnit["kind"]) {
  const definition = unitDefinitions.find((unit) => unit.kind === kind);
  if (!definition) {
    throw new Error(`Unknown Shieldline unit kind: ${kind}`);
  }
  return definition;
}
