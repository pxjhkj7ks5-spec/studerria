import { archetypeLabel } from "./threatDirector";
import type { AfterActionReport, CycleSnapshot, GameState, InfrastructureKind } from "../types/game";

function avg(values: number[]) {
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
}

function systemAverage(state: GameState, kind: InfrastructureKind) {
  return avg(state.infrastructure.filter((node) => node.kind === kind).map((node) => node.integrity));
}

export function createCycleSnapshot(state: GameState): CycleSnapshot {
  return {
    day: state.day,
    resources: { ...state.resources },
    cities: state.cities.map((city) => ({ ...city })),
    infrastructure: state.infrastructure.map((node) => ({ ...node })),
    batteries: state.batteries.map((battery) => ({ ...battery })),
    interceptions: state.interceptions,
    impacts: state.impacts,
    ammo: state.resources.ammo,
    threatCount: state.liveThreats.length,
  };
}

export function generateAfterActionReport(state: GameState, snapshot: CycleSnapshot): AfterActionReport {
  const plan = state.currentAttackPlan;
  const cycleInterceptions = state.interceptions - snapshot.interceptions;
  const cycleImpacts = state.impacts - snapshot.impacts;
  const ammoSpent = Math.max(0, snapshot.ammo - state.resources.ammo);
  const confirmedThreats = cycleInterceptions + cycleImpacts;
  const decoys = Math.round((plan?.deception || 1) + state.liveThreats.filter((threat) => threat.kind === "decoy").length);
  const totalTracks = Math.max(snapshot.threatCount + confirmedThreats + decoys, confirmedThreats + decoys);
  const unidentifiedTracks = Math.max(0, totalTracks - confirmedThreats - decoys);
  const damagedCities = state.cities
    .filter((city) => {
      const before = snapshot.cities.find((item) => item.id === city.id);
      return before ? city.damage > before.damage + 0.5 : city.damage > 0;
    })
    .map((city) => city.name);
  const readinessBefore = avg(snapshot.batteries.map((battery) => battery.readiness));
  const readinessAfter = avg(state.batteries.map((battery) => battery.readiness));
  const strongest = [...state.batteries].sort((left, right) => right.readiness - left.readiness)[0];
  const weakestCity = [...state.cities].sort((left, right) => {
    const leftUnits = state.batteries.filter((battery) => battery.assignedCityId === left.id).length;
    const rightUnits = state.batteries.filter((battery) => battery.assignedCityId === right.id).length;
    return (left.infrastructure + leftUnits * 18) - (right.infrastructure + rightUnits * 18);
  })[0];
  const recommendation = chooseRecommendation(state, ammoSpent);
  const actionEffects = state.planningActions.selected.length
    ? state.planningActions.selected.map((id) => actionLabel(id))
    : ["No strategic action selected."];
  const logisticsNotes = [
    `${state.logistics.routes.filter((route) => route.status === "undersupplied").length} undersupplied abstract route(s).`,
    `Resupply delay ${state.logistics.resupplyDelayDays} cycle(s).`,
  ];

  return {
    id: `aar-${snapshot.day}-${Math.round(state.elapsedMs)}`,
    day: snapshot.day,
    generatedAtMs: state.elapsedMs,
    archetype: plan?.archetype,
    situationSummary: `${plan ? archetypeLabel(plan.archetype) : "Contact cycle"} resolved with ${cycleInterceptions} intercepts and ${cycleImpacts} impacts.`,
    threatOverview: {
      totalTracks,
      confirmedThreats,
      decoys,
      unidentifiedTracks,
    },
    defensePerformance: {
      interceptions: cycleInterceptions,
      missedThreats: cycleImpacts,
      ammoSpent,
      averageReadinessChange: readinessAfter - readinessBefore,
      strongestUnit: strongest ? `${strongest.kind} ${Math.round(strongest.readiness)}%` : "No placed unit",
      weakestCoverageArea: weakestCity ? weakestCity.name : "Unknown",
    },
    damageReport: {
      damagedCities,
      systems: {
        infrastructure: avg(state.cities.map((city) => city.infrastructure)),
        energy: systemAverage(state, "energy"),
        communications: systemAverage(state, "communications"),
        logistics: systemAverage(state, "logistics"),
        civilMorale: avg(state.cities.map((city) => city.morale)),
        repairCapacity: Math.max(0, 100 - avg(state.cities.map((city) => city.damage))),
      },
    },
    resourceChanges: {
      budget: state.resources.budget - snapshot.resources.budget,
      ammo: state.resources.ammo - snapshot.resources.ammo,
      energy: state.resources.energy - snapshot.resources.energy,
      morale: state.resources.morale - snapshot.resources.morale,
      political: state.resources.political - snapshot.resources.political,
    },
    recommendation,
    actionEffects,
    logisticsNotes,
  };
}

function chooseRecommendation(state: GameState, ammoSpent: number) {
  const radarCount = state.batteries.filter((battery) => battery.kind === "radar").length;
  if (radarCount < 2 || state.liveThreats.some((threat) => threat.confidence < 45)) return "Improve radar coverage with abstract sensor assets.";
  if (state.resources.energy < 55 || systemAverage(state, "energy") < 58) return "Prioritize energy grid repair before the next attack cycle.";
  if (state.resources.ammo < 30 || ammoSpent > 25) return "Conserve ammo and let stronger coverage handle confirmed tracks.";
  if (state.logistics.resupplyDelayDays > 0) return "Improve logistics capacity to reduce resupply delays.";
  if (state.resources.political >= 24 && (state.resources.budget < 35 || state.resources.ammo < 45)) return "Request emergency aid while political capital remains available.";
  if (state.resources.morale < 55) return "Protect morale with civil support actions.";
  return "Move mobile defense toward the weakest abstract coverage area.";
}

function actionLabel(id: string) {
  return {
    "high-alert": "High Alert increased detection pressure and fatigue.",
    "conserve-ammo": "Conserve Ammo reduced expenditure but lowered engagement confidence.",
    "emergency-aid": "Emergency Aid created delayed support through logistics.",
    "energy-repair": "Energy Repair improved grid stability.",
    "morale-campaign": "Morale Campaign stabilized civil morale.",
    "rapid-redeployment": "Rapid Redeployment increased fatigue for mobile teams.",
    "intelligence-focus": "Intelligence Focus improved identification confidence.",
  }[id] || id;
}
