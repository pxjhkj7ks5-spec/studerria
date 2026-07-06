import { initialCities, initialInfrastructure } from "../data/mapData";
import { initialLaunchSectors } from "../data/launchSectors";
import { getCampaignModeDefinition } from "../data/campaignModes";
import { getScenario } from "../data/scenarios";
import { unitDefinitions } from "../data/units";
import { buildLogisticsState } from "./logistics";
import type { CampaignMode, City, DailyForecast, DeployedUnit, GameState, IntelEntry, LiveThreat } from "../types/game";

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
    title: "Intel Briefing",
    body: "Multiple disruptions are possible this week. Preserve energy, morale, and repair capacity.",
    tone: "info",
  },
  {
    id: "safety-1",
    time: "T+00:00",
    title: "Simulation Scope",
    body: "Shieldline uses fictional, abstract mechanics. It does not model real deployments or ranges.",
    tone: "info",
  },
];

function createOpeningThreat(): LiveThreat {
  const targetCity = initialCities.find((city) => city.id === "kyiv") || initialCities[0];
  return {
    id: "opening-track-1",
    kind: "geran2",
    status: "inbound",
    origin: { lat: 51.8, lng: 40.0 },
    target: targetCity.coordinates,
    targetCityId: targetCity.id,
    launchSectorId: "drone-northwest",
    launchSectorName: "Northwest Drone Launch Area",
    progress: 0.02,
    speed: 0.0000055,
    difficulty: 28,
    damage: 3,
    detected: false,
    confidence: 32,
    saturation: 1,
    headingDeg: 240,
    revealed: false,
    trackQuality: 0,
    reward: 2,
  };
}

export function createForecast(day: number, random: () => number): DailyForecast {
  const roll = random();
  const weather = roll > 0.84 ? "storm" : roll > 0.64 ? "poor" : "clear";
  const supportDelay = random() > 0.78;
  const pressure = Math.round(10 + random() * 25 + day * 0.7);
  const warningBank = [
    "Signals suggest a mixed pressure campaign, but target confidence is low.",
    "Analysts report unusual routing patterns near major cities.",
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

export function createInitialState(random: () => number = Math.random, mode: CampaignMode = "crisis"): GameState {
  const modeDefinition = getCampaignModeDefinition(mode);
  const scenario = getScenario(mode === "training" ? "first-night" : mode === "seven-day" ? "grid-pressure" : mode === "sandbox" ? "decoy-storm" : "thirty-days-under-pressure");
  const cities = initialCities.map((city) => applyCityModifier(city, scenario.initialCityStateModifiers[city.id]));
  const state: GameState = {
    day: 1,
    scenarioId: scenario.id,
    difficulty: scenario.difficulty,
    cyclePhase: "planning",
    cycleStartedAtMs: 0,
    cycleDurationMs: 180000,
    currentAttackPlan: null,
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
    launchSectors: initialLaunchSectors.map((sector) => ({
      ...sector,
      coordinates: { ...sector.coordinates },
      supports: [...sector.supports],
    })),
    carriers: [],
    pendingLaunches: [],
    units: initialUnits.map((unit) => ({ ...unit })),
    batteries: [],
    liveThreats: [createOpeningThreat()],
    interceptorShots: [],
    impactMarkers: [],
    interceptions: 0,
    impacts: 0,
    log: openingLog,
    forecast: createForecast(1, random),
    placementWarning: null,
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
  state.liveThreats = [createOpeningThreat()];
  state.logistics = buildLogisticsState(state);
  state.log.unshift({
    id: `scenario-${scenario.id}`,
    time: "T+00:00",
    title: "Scenario Selected",
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
