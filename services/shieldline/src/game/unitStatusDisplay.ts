import type { DefenseBattery, UnitDefinition } from "../types/game";

export type TacticalUnitStatus = {
  label: "READY" | "ENGAGING" | "RELOADING" | "NO AMMO" | "DAMAGED" | "OFFLINE";
  tone: "ready" | "engaging" | "warning" | "danger" | "offline";
};

export function tacticalUnitStatus(unit: UnitDefinition, battery?: DefenseBattery): TacticalUnitStatus {
  if (!battery) return { label: "READY", tone: "ready" };
  if (battery.status === "maintenance") return { label: "OFFLINE", tone: "offline" };
  if (battery.status === "engaging") return { label: "ENGAGING", tone: "engaging" };
  if (battery.reloadRemainingMs > 0 || battery.status === "reloading") return { label: "RELOADING", tone: "warning" };
  if (unit.ammoCapacity !== 0 && unit.ammoCapacity !== "infinite" && battery.currentAmmo === 0) return { label: "NO AMMO", tone: "danger" };
  if (battery.readiness < 50 || battery.status === "exhausted") return { label: "DAMAGED", tone: "danger" };
  return { label: "READY", tone: "ready" };
}
