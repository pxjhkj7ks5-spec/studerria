import type { UnitStatus } from "../types/game";

export function unitMarkerStatusClass(status: UnitStatus) {
  return `map-marker--unit-${status}`;
}
