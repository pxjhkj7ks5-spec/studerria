import type { DefenseBattery } from "../types/game";

export function batteryCoverageUnavailable(battery: Pick<DefenseBattery, "status" | "currentAmmo">) {
  return battery.status === "maintenance" || battery.currentAmmo === 0;
}
