import type { GameState, PlanningActionId } from "../types/game";
import { clamp } from "./math";

export interface PlanningActionDefinition {
  id: PlanningActionId;
  title: string;
  description: string;
  cooldownDays: number;
  cost: Partial<Record<"budget" | "ammo" | "energy" | "morale" | "political", number>>;
}

export const planningActionDefinitions: PlanningActionDefinition[] = [
  {
    id: "high-alert",
    title: "High Alert",
    description: "Improves detection this cycle, but strains energy and unit fatigue.",
    cooldownDays: 1,
    cost: { energy: 4 },
  },
  {
    id: "conserve-ammo",
    title: "Conserve Ammo",
    description: "Reduces ammo spend while lowering interception confidence.",
    cooldownDays: 0,
    cost: {},
  },
  {
    id: "emergency-aid",
    title: "Emergency Aid Request",
    description: "Spends political capital for delayed budget and ammunition support.",
    cooldownDays: 3,
    cost: { political: 12 },
  },
  {
    id: "energy-repair",
    title: "Prioritize Energy Repair",
    description: "Uses budget to restore national energy and city energy systems.",
    cooldownDays: 1,
    cost: { budget: 16 },
  },
  {
    id: "morale-campaign",
    title: "Morale Campaign",
    description: "Improves civil morale at budget and political cost.",
    cooldownDays: 2,
    cost: { budget: 10, political: 8 },
  },
  {
    id: "rapid-redeployment",
    title: "Rapid Redeployment",
    description: "Allows aggressive mobile repositioning while increasing fatigue.",
    cooldownDays: 2,
    cost: { budget: 8 },
  },
  {
    id: "intelligence-focus",
    title: "Intelligence Focus",
    description: "Improves threat identification for the coming attack cycle.",
    cooldownDays: 1,
    cost: { budget: 12 },
  },
];

export function getPlanningAction(id: PlanningActionId) {
  return planningActionDefinitions.find((action) => action.id === id) || planningActionDefinitions[0];
}

export function canSelectAction(state: GameState, actionId: PlanningActionId) {
  if (state.cyclePhase !== "planning") return false;
  if (state.planningActions.selected.includes(actionId)) return true;
  if (state.planningActions.selected.length >= 2) return false;
  if ((state.planningActions.cooldowns[actionId] || 0) > 0) return false;
  const action = getPlanningAction(actionId);
  return Object.entries(action.cost).every(([key, cost]) => state.resources[key as keyof typeof state.resources] >= (cost || 0));
}

export function togglePlanningAction(state: GameState, actionId: PlanningActionId): GameState {
  if (!canSelectAction(state, actionId)) return state;
  const selected = state.planningActions.selected.includes(actionId)
    ? state.planningActions.selected.filter((id) => id !== actionId)
    : [...state.planningActions.selected, actionId];
  return {
    ...state,
    planningActions: {
      ...state.planningActions,
      selected,
    },
  };
}

export function applyPlanningActionCosts(state: GameState) {
  for (const actionId of state.planningActions.selected) {
    const action = getPlanningAction(actionId);
    for (const [key, value] of Object.entries(action.cost)) {
      const resourceKey = key as keyof typeof state.resources;
      state.resources[resourceKey] = clamp(state.resources[resourceKey] - (value || 0), 0, 999);
    }
    state.planningActions.usageCounts[actionId] = (state.planningActions.usageCounts[actionId] || 0) + 1;
    state.planningActions.cooldowns[actionId] = action.cooldownDays;
  }
  if (state.planningActions.selected.includes("emergency-aid")) {
    const delay = Math.max(1, 2 + state.logistics.resupplyDelayDays);
    state.planningActions.pendingAid.push({
      arrivesDay: state.day + delay,
      budget: 24,
      ammo: 28,
    });
  }
}

export function applyPlanningRecoveryEffects(state: GameState) {
  if (state.planningActions.selected.includes("energy-repair")) {
    state.resources.energy = clamp(state.resources.energy + 7, 0, 100);
    for (const city of state.cities) {
      city.energy = clamp(city.energy + 4, 0, 100);
    }
    for (const node of state.infrastructure.filter((item) => item.kind === "energy")) {
      node.integrity = clamp(node.integrity + 6, 0, 100);
    }
  }
  if (state.planningActions.selected.includes("morale-campaign")) {
    state.resources.morale = clamp(state.resources.morale + 6, 0, 100);
    for (const city of state.cities) {
      city.morale = clamp(city.morale + 3, 0, 100);
    }
  }
}

export function closePlanningDay(state: GameState) {
  for (const key of Object.keys(state.planningActions.cooldowns) as PlanningActionId[]) {
    state.planningActions.cooldowns[key] = Math.max(0, (state.planningActions.cooldowns[key] || 0) - 1);
  }
  const arrived = state.planningActions.pendingAid.filter((aid) => aid.arrivesDay <= state.day);
  if (arrived.length) {
    for (const aid of arrived) {
      state.resources.budget = clamp(state.resources.budget + aid.budget, 0, 999);
      state.resources.ammo = clamp(state.resources.ammo + aid.ammo, 0, 999);
    }
    state.planningActions.pendingAid = state.planningActions.pendingAid.filter((aid) => aid.arrivesDay > state.day);
  }
  state.planningActions.selected = [];
}
