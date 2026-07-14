import type { DefenseBattery } from "../types/game";

export function batteryCoverageState(battery: Pick<DefenseBattery, "status" | "currentAmmo">) {
  if (battery.currentAmmo === 0) return "empty" as const;
  if (battery.status === "maintenance") return "maintenance" as const;
  return "ready" as const;
}

export function batteryCoverageUnavailable(battery: Pick<DefenseBattery, "status" | "currentAmmo">) {
  return batteryCoverageState(battery) !== "ready";
}
