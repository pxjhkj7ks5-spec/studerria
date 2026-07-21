import { initialCities, initialInfrastructure } from "../data/mapData";
import { getCampaignModeDefinition } from "../data/campaignModes";
import { getScenario } from "../data/scenarios";
import { unitDefinitions } from "../data/units";
import { buildLogisticsState } from "./logistics";
import { createLaunchSectorState } from "./launchSystem.mjs";
import type { CampaignMode, City, DailyForecast, DeployedUnit, GameState, IntelEntry } from "../types/game";

const initialUnits: DeployedUnit[] = [
  { id: "seed-radar-kyiv", kind: "radar", cityId: "kyiv", readiness: 86 },
  { id: "seed-mvg-dnipro", kind: "mvg", cityId: "dnipro", readiness: 82 },
  { id: "seed-ew-odesa", kind: "ew", cityId: "odesa", readiness: 84 },
  { id: "seed-manpads-kharkiv", kind: "manpads", cityId: "kharkiv", readiness: 84 },
];

const openingLog: IntelEntry[] = [
  {
    id: "briefing-1",
    time: "T+00:00",
    title: "Розвідувальне зведення",
    body: "Протягом операції можливі численні загрози. Зберігайте енергію, мораль і ремонтний резерв.",
    tone: "info",
  },
  {
    id: "safety-1",
    time: "T+00:00",
    title: "Межі симуляції",
    body: "Shieldline використовує умовні абстрактні механіки й не моделює реальні позиції або дальності.",
    tone: "info",
  },
];

export function createForecast(day: number, random: () => number): DailyForecast {
  const roll = random();
  const weather = roll > 0.84 ? "storm" : roll > 0.64 ? "poor" : "clear";
  const supportDelay = random() > 0.78;
  const pressure = Math.round(10 + random() * 25 + day * 0.7);
  const warningBank = [
    "Сигнали вказують на змішану атаку, але достовірність цілей залишається низькою.",
    "Аналітики фіксують незвичні маршрути поблизу великих міст.",
    "Групи підтримки очікують складний період технічного обслуговування.",
    "Кілька попереджень суперечать одне одному. Зберігайте гнучкий резерв.",
  ];

  return {
    day,
    weather,
    supportDelay,
    pressure,
    vagueWarning: warningBank[Math.floor(random() * warningBank.length)] || warningBank[0],
  };
}

export function createInitialState(random: () => number = Math.random, mode: CampaignMode = "crisis"): GameState {
  const modeDefinition = getCampaignModeDefinition(mode);
  const scenario = getScenario(mode === "training" ? "first-night" : mode === "seven-day" ? "grid-pressure" : mode === "sandbox" ? "decoy-storm" : "thirty-days-under-pressure");
  const cities = initialCities.map((city) => applyCityModifier(city, scenario.initialCityStateModifiers[city.id]));
  const launchSectors = createLaunchSectorState();
  const state: GameState = {
    day: 1,
    scenarioId: scenario.id,
    difficulty: scenario.difficulty,
    cyclePhase: "planning",
    cycleStartedAtMs: 0,
    cycleDurationMs: 180000,
    currentAttackPlan: null,
    campaignAttackSchedule: null,
    attackPlanHistory: [],
    cycleSnapshot: null,
    afterActionReports: [],
    latestReportId: null,
    planningActions: {
      selected: [],
      cooldowns: {},
      usageCounts: {},
      pendingAid: [],
    },
    logistics: {
      nodes: [],
      routes: [],
      citySupply: {},
      unitSupply: {},
      resupplyDelayDays: 0,
      ammoRecoveryMultiplier: 1,
      repairRecoveryMultiplier: 1,
    },
    elapsedMs: 0,
    wavePressure: 18,
    status: "active",
    statusReason: "",
    resources: { ...modeDefinition.resources, ...scenario.startingResources },
    cities,
    infrastructure: initialInfrastructure.map((node) => ({ ...node })),
    launchSectors,
    carriers: [],
    pendingLaunches: [],
    units: initialUnits.map((unit) => ({ ...unit })),
    batteries: [],
    storedBatteries: [],
    liveThreats: [],
    engagementEvents: [],
    impactMarkers: [],
    interceptions: 0,
    softKills: 0,
    impacts: 0,
    log: openingLog,
    forecast: createForecast(1, random),
    placementWarning: null,
    campaign: null,
  };
  state.logistics = buildLogisticsState(state);
  return state;
}

export function createScenarioState(random: () => number = Math.random, mode: CampaignMode = "crisis", scenarioId = "thirty-days-under-pressure"): GameState {
  const scenario = getScenario(scenarioId);
  const state = createInitialState(random, mode);
  state.scenarioId = scenario.id;
  state.difficulty = scenario.difficulty;
  state.resources = { ...scenario.startingResources };
  state.cities = initialCities.map((city) => applyCityModifier(city, scenario.initialCityStateModifiers[city.id]));
  state.liveThreats = [];
  state.logistics = buildLogisticsState(state);
  state.log.unshift({
    id: `scenario-${scenario.id}`,
    time: "T+00:00",
    title: "Сценарій обрано",
    body: `${scenario.title}: ${scenario.description}`,
    tone: "info",
  });
  return state;
}

function applyCityModifier(city: City, modifier: Partial<Pick<City, "infrastructure" | "morale" | "energy" | "damage">> | undefined): City {
  return {
    ...city,
    ...(modifier || {}),
  };
}

export function getUnitDefinition(kind: DeployedUnit["kind"]) {
  const definition = unitDefinitions.find((unit) => unit.kind === kind);
  if (!definition) {
    throw new Error(`Unknown Shieldline unit kind: ${kind}`);
  }
  return definition;
}
