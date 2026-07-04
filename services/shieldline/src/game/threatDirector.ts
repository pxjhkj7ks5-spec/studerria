import type {
  AttackArchetype,
  AttackPlan,
  GameState,
  InfrastructureKind,
  ScenarioDefinition,
  ThreatDirectorContext,
  ThreatKind,
} from "../types/game";
import { createId, pick } from "./math";

const archetypeThreats: Record<AttackArchetype, ThreatKind[]> = {
  probe: ["gerbera", "parodiya", "geran2"],
  saturation: ["geran2", "gerbera", "parodiya", "geran2"],
  infrastructure: ["kh101", "kalibr", "geran2", "iskander"],
  "decoy-screen": ["parodiya", "gerbera", "parodiya"],
  pressure: ["geran2", "kh101", "parodiya"],
  combined: ["geran2", "kh101", "kalibr", "iskander", "parodiya"],
};

const archetypeTargets: Record<AttackArchetype, InfrastructureKind[]> = {
  probe: ["communications", "logistics"],
  saturation: ["industry", "communications", "logistics"],
  infrastructure: ["energy", "logistics", "communications"],
  "decoy-screen": ["communications", "logistics"],
  pressure: ["energy", "industry", "communications"],
  combined: ["energy", "logistics", "communications", "industry"],
};

export function createThreatDirectorContext(state: GameState, scenario: ScenarioDefinition): ThreatDirectorContext {
  const avgCityDamage = state.cities.reduce((sum, city) => sum + city.damage, 0) / Math.max(1, state.cities.length);
  const avgConfidence = state.liveThreats.length
    ? state.liveThreats.reduce((sum, threat) => sum + threat.confidence, 0) / state.liveThreats.length
    : 56;
  const weakSystems = ["energy", "logistics", "communications", "industry"]
    .map((kind) => ({
      kind: kind as InfrastructureKind,
      score: state.infrastructure
        .filter((node) => node.kind === kind)
        .reduce((sum, node, _, arr) => sum + node.integrity / Math.max(1, arr.length), 0),
    }))
    .sort((left, right) => left.score - right.score)
    .slice(0, 2)
    .map((entry) => entry.kind);

  return {
    resources: state.resources,
    cityDamage: avgCityDamage,
    placedDefenseUnits: state.batteries.length,
    ammoLevel: state.resources.ammo,
    moraleLevel: state.resources.morale,
    energyStability: state.resources.energy,
    intelligenceConfidence: avgConfidence,
    currentDay: state.day,
    difficulty: state.difficulty,
    recentArchetypes: state.attackPlanHistory.slice(-3).map((plan) => plan.archetype),
    weakSystems,
    threatDirectorBias: scenario.threatDirectorBias,
  };
}

function difficultyRamp(context: ThreatDirectorContext) {
  const dayRamp = Math.min(1, context.currentDay / 12);
  const difficulty = { training: 0.72, standard: 1, hard: 1.18, endurance: 1.28 }[context.difficulty];
  return difficulty * (0.72 + dayRamp * 0.45);
}

function scoreArchetype(archetype: AttackArchetype, context: ThreatDirectorContext) {
  let score = 20 * (context.threatDirectorBias?.[archetype] || 1);
  if (archetype === "probe" && context.currentDay <= 2) score += 20;
  if (archetype === "saturation" && context.ammoLevel < 70) score += 18;
  if (archetype === "infrastructure" && (context.energyStability < 72 || context.weakSystems.includes("energy"))) score += 22;
  if (archetype === "decoy-screen" && context.intelligenceConfidence < 62) score += 18;
  if (archetype === "pressure" && context.moraleLevel < 78) score += 16;
  if (archetype === "combined" && context.currentDay >= 5) score += 18;
  if (archetype === "combined" && context.currentDay < 4) score -= 26;
  if (context.recentArchetypes.at(-1) === archetype) score -= 16;
  if (context.recentArchetypes.slice(-2).every((item) => item === archetype)) score -= 999;
  if (context.placedDefenseUnits < 2 && archetype !== "probe") score -= 10;
  return score;
}

function weightedPick(scores: Array<{ archetype: AttackArchetype; score: number }>, random: () => number) {
  const positive = scores.map((entry) => ({ ...entry, score: Math.max(1, entry.score) }));
  const total = positive.reduce((sum, entry) => sum + entry.score, 0);
  let roll = random() * total;
  for (const entry of positive) {
    roll -= entry.score;
    if (roll <= 0) return entry.archetype;
  }
  return positive[0].archetype;
}

export function chooseAttackPlan(context: ThreatDirectorContext, random: () => number = Math.random): AttackPlan {
  // The director scores fictional pressure patterns against abstract weaknesses, then
  // penalizes recent repeats so attacks feel adaptive without becoming operational advice.
  const archetypes: AttackArchetype[] = ["probe", "saturation", "infrastructure", "decoy-screen", "pressure", "combined"];
  const archetype = weightedPick(archetypes.map((item) => ({ archetype: item, score: scoreArchetype(item, context) })), random);
  const ramp = difficultyRamp(context);
  const baseIntensity = {
    probe: 1.2,
    saturation: 2.8,
    infrastructure: 2.1,
    "decoy-screen": 1.8,
    pressure: 2.0,
    combined: 2.7,
  }[archetype];
  const intensity = Math.min(5.2, Math.max(1, baseIntensity * ramp + random() * 0.7));
  const deception = Math.min(5, Math.max(0.4, (archetype === "decoy-screen" ? 3.2 : archetype === "combined" ? 2.3 : 1.1) * ramp));
  const targetPriorities = [...new Set([...context.weakSystems, ...archetypeTargets[archetype]])].slice(0, 3);
  return {
    id: createId("attack-plan", context.currentDay, random),
    day: context.currentDay,
    archetype,
    intensity,
    deception,
    targetPriorities,
    threatMix: archetypeThreats[archetype],
    eventText: planText(archetype, intensity, deception),
  };
}

export function pickThreatKindForPlan(plan: AttackPlan, random: () => number) {
  return pick(plan.threatMix, random);
}

function planText(archetype: AttackArchetype, intensity: number, deception: number) {
  const label = archetypeLabel(archetype);
  return `${label} forming: intensity ${Math.round(intensity)}/5, deception ${Math.round(deception)}/5.`;
}

export function archetypeLabel(archetype: AttackArchetype) {
  return {
    probe: "Probe attack",
    saturation: "Saturation raid",
    infrastructure: "Infrastructure strike",
    "decoy-screen": "Decoy screen",
    pressure: "Pressure campaign",
    combined: "Combined attack",
  }[archetype];
}
