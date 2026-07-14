import type { DefenseBattery, UnitDefinition } from "../types/game";

export function batteryCoverageState(
  battery: Pick<DefenseBattery, "status" | "currentAmmo">,
  ammoCapacity?: UnitDefinition["ammoCapacity"],
) {
  if (battery.status === "maintenance") return "maintenance" as const;
  if (ammoCapacity !== 0 && battery.currentAmmo === 0) return "empty" as const;
  return "ready" as const;
}

export function batteryCoverageUnavailable(
  battery: Pick<DefenseBattery, "status" | "currentAmmo">,
  ammoCapacity?: UnitDefinition["ammoCapacity"],
) {
  return batteryCoverageState(battery, ammoCapacity) !== "ready";
}
