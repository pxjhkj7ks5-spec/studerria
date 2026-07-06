import { eventDeck } from "../data/events";
import { unitDefinitions } from "../data/units";
import type {
  City,
  CityId,
  DailyForecast,
  DeployedUnit,
  GameState,
  IntelEntry,
  Threat,
  ThreatKind,
  UnitKind,
} from "../types/game";
import { createForecast, getUnitDefinition } from "./initialState";
import { clamp, createId, pick, weightedChance } from "./math";

const threatKinds: ThreatKind[] = ["drone", "ballistic", "cruise", "decoy", "combined", "saturation"];

function cloneState(state: GameState): GameState {
  return {
    ...state,
    resources: { ...state.resources },
    cities: state.cities.map((city) => ({ ...city })),
    infrastructure: state.infrastructure.map((node) => ({ ...node })),
    units: state.units.map((unit) => ({ ...unit })),
    log: state.log.map((entry) => ({ ...entry })),
    forecast: { ...state.forecast },
  };
}

function pushLog(entries: IntelEntry[], day: number, title: string, body: string, tone: IntelEntry["tone"]) {
  entries.unshift({
    id: `${day}-${entries.length}-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
    time: `Day ${day}`,
    title,
    body,
    tone,
  });
}

function getCity(state: GameState, cityId: CityId) {
  const city = state.cities.find((item) => item.id === cityId);
  if (!city) throw new Error(`Unknown city: ${cityId}`);
  return city;
}

function unitsAtCity(units: DeployedUnit[], cityId: CityId) {
  return units.filter((unit) => unit.cityId === cityId);
}

function averageReadiness(units: DeployedUnit[]) {
  if (!units.length) return 0;
  return units.reduce((sum, unit) => sum + unit.readiness, 0) / units.length;
}

function forecastDetectionPenalty(forecast: DailyForecast) {
  if (forecast.weather === "storm") return 18;
  if (forecast.weather === "poor") return 9;
  return 0;
}

function generateThreats(state: GameState, random: () => number): Threat[] {
  const count = state.day > 20 ? 3 : state.day > 10 ? 2 : 1 + (random() > 0.72 ? 1 : 0);
  const threats: Threat[] = [];

  for (let index = 0; index < count; index += 1) {
    const city = pick(state.cities, random);
    const kind = pick(threatKinds, random);
    const pressureBonus = state.forecast.pressure / 12;
    const difficultyByKind: Record<ThreatKind, number> = {
      drone: 28,
      ballistic: 50,
      cruise: 42,
      decoy: 22,
      combined: 52,
      saturation: 60,
      geran2: 28,
      gerbera: 22,
      parodiya: 18,
      kh101: 42,
      kalibr: 42,
      iskander: 50,
    };

    threats.push({
      id: createId("threat", state.day, random),
      kind,
      targetCityId: city.id,
      difficulty: difficultyByKind[kind] + pressureBonus + random() * 12,
      saturation: kind === "saturation" ? 1.7 : kind === "combined" ? 1.3 : 1,
      disguisedAs: random() > 0.68 ? pick(threatKinds, random) : undefined,
    });
  }

  return threats;
}

function identifyThreat(threat: Threat, cityUnits: DeployedUnit[], forecast: DailyForecast, random: () => number) {
  const intelScore = cityUnits.reduce((score, unit) => {
    const definition = getUnitDefinition(unit.kind);
    return score + definition.detectionBonus * (unit.readiness / 100);
  }, 28);
  const chance = intelScore - forecastDetectionPenalty(forecast) - threat.saturation * 6;

  if (weightedChance(chance, random)) return threat.kind;
  return threat.disguisedAs || "decoy";
}

function resolveThreat(state: GameState, threat: Threat, random: () => number) {
  const targetCity = getCity(state, threat.targetCityId);
  const cityUnits = unitsAtCity(state.units, targetCity.id);
  const identifiedAs = identifyThreat(threat, cityUnits, state.forecast, random);
  const detectionScore = cityUnits.reduce((score, unit) => {
    const definition = getUnitDefinition(unit.kind);
    return score + definition.detectionBonus * (unit.readiness / 100);
  }, 24) - forecastDetectionPenalty(state.forecast);
  const detected = weightedChance(detectionScore - threat.difficulty * 0.32, random);

  const defenseUnits = cityUnits.filter((unit) => {
    const definition = getUnitDefinition(unit.kind);
    return definition.interceptionPower > 0;
  });
  const ammoNeed = defenseUnits.reduce((sum, unit) => sum + getUnitDefinition(unit.kind).ammoUse, 0);
  const ammoRatio = ammoNeed > 0 ? clamp(state.resources.ammo / ammoNeed, 0, 1) : 0;
  const interceptionPower = defenseUnits.reduce((score, unit) => {
    const definition = getUnitDefinition(unit.kind);
    return score + definition.interceptionPower * (unit.readiness / 100);
  }, 0);
  const decoyBuffer = cityUnits.some((unit) => unit.kind === "ew") ? 8 : 0;
  const interceptionChance = detected
    ? interceptionPower * ammoRatio + decoyBuffer - threat.difficulty - (threat.saturation - 1) * 18
    : decoyBuffer - threat.difficulty * 0.6;
  const intercepted = threat.kind === "decoy" || weightedChance(interceptionChance, random);

  if (ammoNeed > 0 && detected) {
    state.resources.ammo = clamp(state.resources.ammo - Math.ceil(ammoNeed * Math.min(1, threat.saturation)), 0, 999);
  }

  const readinessDrain = detected ? 4 + threat.saturation * 3 : 2;
  state.units = state.units.map((unit) => {
    if (unit.cityId !== targetCity.id) return unit;
    return { ...unit, readiness: clamp(unit.readiness - readinessDrain, 35, 100) };
  });

  if (intercepted) {
    pushLog(
      state.log,
      state.day,
      "Threat Contained",
      `${targetCity.name} handled a ${identifiedAs} warning with limited disruption.`,
      "success",
    );
    state.resources.morale = clamp(state.resources.morale + 1);
    return;
  }

  const damage = Math.round(9 + threat.difficulty * 0.22 + random() * 10);
  targetCity.damage = clamp(targetCity.damage + damage * 0.45);
  targetCity.infrastructure = clamp(targetCity.infrastructure - damage * 0.35);
  targetCity.energy = clamp(targetCity.energy - damage * 0.25);
  targetCity.morale = clamp(targetCity.morale - damage * 0.2);

  state.resources.energy = clamp(state.resources.energy - damage * 0.14);
  state.resources.morale = clamp(state.resources.morale - (targetCity.importance + damage * 0.08));
  state.resources.political = clamp(state.resources.political - Math.max(2, targetCity.importance));

  pushLog(
    state.log,
    state.day,
    "City Hit",
    `${targetCity.name} took damage after an uncertain ${identifiedAs} report.`,
    "danger",
  );
}

function applyRepairs(state: GameState) {
  for (const city of state.cities) {
    const localLogistics = state.infrastructure.find((node) => node.cityId === city.id && node.kind === "logistics");
    const repairAmount = localLogistics ? Math.max(0, localLogistics.integrity - 45) * 0.025 : 0.6;
    city.damage = clamp(city.damage - repairAmount * 0.4);
    city.infrastructure = clamp(city.infrastructure + repairAmount * 0.2);
    city.energy = clamp(city.energy + repairAmount * 0.16);
  }
}

function applyRandomEvent(state: GameState, random: () => number) {
  if (random() < 0.34) return;

  const event = pick(eventDeck, random);
  state.resources.budget = clamp(state.resources.budget + event.budget, 0, 999);
  state.resources.ammo = clamp(state.resources.ammo + event.ammo, 0, 999);
  state.resources.energy = clamp(state.resources.energy + event.energy);
  state.resources.morale = clamp(state.resources.morale + event.morale);
  state.resources.political = clamp(state.resources.political + event.political);
  pushLog(state.log, state.day, event.title, event.body, event.energy < -3 || event.morale < -2 ? "warning" : "info");
}

function applyResourceProduction(state: GameState) {
  const averageNodeIntegrity = state.infrastructure.reduce((sum, node) => sum + node.integrity, 0)
    / state.infrastructure.length;
  const logisticsNodes = state.infrastructure.filter((node) => node.kind === "logistics");
  const logisticsBonus = logisticsNodes.length
    ? logisticsNodes.reduce((sum, node) => sum + node.integrity, 0) / logisticsNodes.length / 12
    : 0;
  const upkeep = state.units.reduce((sum, unit) => sum + getUnitDefinition(unit.kind).upkeep, 0);

  state.resources.budget = clamp(state.resources.budget + 20 + averageNodeIntegrity / 12 + logisticsBonus - upkeep, 0, 999);
  state.resources.ammo = clamp(state.resources.ammo + 10 + logisticsBonus * 0.55, 0, 999);
  state.resources.energy = clamp(state.resources.energy + (averageNodeIntegrity - 70) / 10);
  state.resources.morale = clamp(state.resources.morale + (state.resources.energy > 55 ? 1.5 : -3));
  state.resources.political = clamp(state.resources.political + 3 - state.forecast.pressure / 20);
}

function updateReadiness(state: GameState) {
  state.units = state.units.map((unit) => {
    const localLogistics = state.infrastructure.some((node) => node.cityId === unit.cityId && node.kind === "logistics" && node.integrity > 55);
    const recovery = localLogistics ? 5 : 2;
    return { ...unit, readiness: clamp(unit.readiness + recovery, 35, 100) };
  });
}

function evaluateStatus(state: GameState) {
  const collapsedCities = state.cities.filter((city) => city.infrastructure <= 0 || city.damage >= 100).length;
  if (state.resources.morale <= 0) {
    state.status = "lost";
    state.statusReason = "National morale collapsed.";
  } else if (state.resources.energy <= 0) {
    state.status = "lost";
    state.statusReason = "Energy stability collapsed.";
  } else if (collapsedCities >= 3) {
    state.status = "lost";
    state.statusReason = "Too many cities lost essential services.";
  } else if (state.day > 30) {
    state.status = "won";
    state.statusReason = "The 30-day crisis campaign was survived.";
  }
}

export function advanceDay(current: GameState, random: () => number = Math.random): GameState {
  if (current.status !== "active") return current;

  const state = cloneState(current);
  pushLog(state.log, state.day, "Daily Briefing", state.forecast.vagueWarning, "info");
  applyRandomEvent(state, random);

  for (const threat of generateThreats(state, random)) {
    resolveThreat(state, threat, random);
  }

  applyRepairs(state);
  applyResourceProduction(state);
  updateReadiness(state);

  state.day += 1;
  state.forecast = createForecast(state.day, random);
  evaluateStatus(state);

  if (state.status === "won") {
    pushLog(state.log, state.day, "Campaign Survived", state.statusReason, "success");
  } else if (state.status === "lost") {
    pushLog(state.log, state.day, "Campaign Failed", state.statusReason, "danger");
  }

  return state;
}

export function purchaseUnit(state: GameState, kind: UnitKind, cityId: CityId, random: () => number = Math.random): GameState {
  const definition = unitDefinitions.find((unit) => unit.kind === kind);
  if (!definition || state.status !== "active" || state.resources.budget < definition.cost) {
    return state;
  }

  const next = cloneState(state);
  next.resources.budget = clamp(next.resources.budget - definition.cost, 0, 999);
  next.units.push({
    id: createId(kind, next.day, random),
    kind,
    cityId,
    readiness: definition.readiness,
  });
  pushLog(next.log, next.day, `${definition.name} Deployed`, `${definition.name} assigned to ${getCity(next, cityId).name}.`, "success");
  return next;
}

export function moveUnit(state: GameState, unitId: string, cityId: CityId): GameState {
  if (state.status !== "active") return state;
  const next = cloneState(state);
  const unit = next.units.find((item) => item.id === unitId);
  if (!unit || unit.cityId === cityId) return next;
  const definition = getUnitDefinition(unit.kind);
  unit.cityId = cityId;
  unit.readiness = clamp(unit.readiness - Math.max(6, 18 - definition.mobility * 3), 35, 100);
  pushLog(next.log, next.day, `${definition.shortName} Moved`, `${definition.name} redeployed to ${getCity(next, cityId).name}.`, "info");
  return next;
}
