import type { DefenseBattery, GameState, LogisticsState, SupplyNode, SupplyRoute, SupplyStatus } from "../types/game";
import { clamp } from "./math";

function abstractDistance(left: { lat: number; lng: number }, right: { lat: number; lng: number }) {
  const lat = left.lat - right.lat;
  const lng = left.lng - right.lng;
  return Math.sqrt(lat * lat + lng * lng);
}

function statusFromScore(score: number): SupplyStatus {
  if (score >= 70) return "well-supplied";
  if (score < 42) return "undersupplied";
  return "strained";
}

export function buildLogisticsState(state: GameState): LogisticsState {
  const nodes: SupplyNode[] = [
    ...state.infrastructure
      .filter((node) => node.kind === "logistics")
      .map((node) => ({
        id: node.id,
        name: node.name,
        position: node.coordinates,
        strength: node.integrity,
        cityId: node.cityId,
        source: "infrastructure" as const,
      })),
  ];

  const citySupply: LogisticsState["citySupply"] = {};
  const unitSupply: Record<string, SupplyStatus> = {};
  const routes: SupplyRoute[] = [];

  for (const city of state.cities) {
    const nearest = nodes
      .map((node) => ({ node, distance: abstractDistance(city.coordinates, node.position) }))
      .sort((left, right) => left.distance - right.distance)[0];
    const baseScore = nearest ? nearest.node.strength - nearest.distance * 11 : 18;
    const status = statusFromScore(baseScore);
    citySupply[city.id] = status;
    if (nearest) {
      routes.push({
        id: `city-route-${city.id}-${nearest.node.id}`,
        from: nearest.node.position,
        to: city.coordinates,
        status,
        delayDays: status === "undersupplied" ? 2 : status === "strained" ? 1 : 0,
        label: `${city.name} ${status.replace("-", " ")}`,
      });
    }
  }

  for (const battery of state.batteries) {
    unitSupply[battery.id] = getUnitSupplyStatus(battery, nodes);
    const nearest = nodes
      .map((node) => ({ node, distance: abstractDistance(battery.position, node.position) }))
      .sort((left, right) => left.distance - right.distance)[0];
    if (nearest) {
      routes.push({
        id: `unit-route-${battery.id}-${nearest.node.id}`,
        from: nearest.node.position,
        to: battery.position,
        status: unitSupply[battery.id],
        delayDays: unitSupply[battery.id] === "undersupplied" ? 2 : unitSupply[battery.id] === "strained" ? 1 : 0,
        label: `Unit ${unitSupply[battery.id].replace("-", " ")}`,
      });
    }
  }

  const routeDelay = routes.length
    ? Math.round(routes.reduce((sum, route) => sum + route.delayDays, 0) / routes.length)
    : 2;
  const healthyRatio = nodes.length ? nodes.reduce((sum, node) => sum + node.strength, 0) / (nodes.length * 100) : 0.35;

  return {
    nodes,
    routes,
    citySupply,
    unitSupply,
    resupplyDelayDays: clamp(routeDelay, 0, 3),
    ammoRecoveryMultiplier: clamp(0.55 + healthyRatio * 0.65, 0.45, 1.25),
    repairRecoveryMultiplier: clamp(0.58 + healthyRatio * 0.55, 0.45, 1.2),
  };
}

export function getUnitSupplyStatus(battery: DefenseBattery, nodes: SupplyNode[]): SupplyStatus {
  const nearest = nodes
    .map((node) => ({ node, distance: abstractDistance(battery.position, node.position) }))
    .sort((left, right) => left.distance - right.distance)[0];
  if (!nearest) return "undersupplied";
  return statusFromScore(nearest.node.strength - nearest.distance * 13);
}
