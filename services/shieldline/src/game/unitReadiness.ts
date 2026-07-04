import type { DefenseBattery, SupplyStatus, UnitKind, UnitStatus } from "../types/game";
import { clamp } from "./math";

export function deriveUnitStatus(battery: Pick<DefenseBattery, "readiness" | "fatigue" | "status">): UnitStatus {
  if (battery.status === "maintenance" || battery.status === "redeploying") return battery.status;
  if (battery.fatigue >= 82 || battery.readiness < 38) return "exhausted";
  if (battery.fatigue >= 58 || battery.readiness < 62) return "strained";
  return "ready";
}

export function supplyRecoveryBonus(status: SupplyStatus) {
  if (status === "well-supplied") return 1.28;
  if (status === "undersupplied") return 0.58;
  return 0.9;
}

export function applyEngagementFatigue(battery: DefenseBattery, ammoUse: number, success: boolean) {
  battery.readiness = clamp(battery.readiness - (success ? 4.2 : 2.1) - ammoUse * 0.2, 8, 100);
  battery.fatigue = clamp(battery.fatigue + (success ? 5.5 : 3.2) + ammoUse * 0.25, 0, 100);
  battery.lastAction = success ? "engaged target" : "failed engagement";
  battery.status = deriveUnitStatus(battery);
}

export function applyRedeployFatigue(battery: DefenseBattery) {
  battery.readiness = clamp(battery.readiness - 10, 8, 100);
  battery.fatigue = clamp(battery.fatigue + 18, 0, 100);
  battery.lastAction = "rapid redeployment";
  battery.status = "redeploying";
}

export function recoverReadiness(battery: DefenseBattery, deltaMs: number, nearbyRepair: boolean, supplyStatus: SupplyStatus) {
  const maintenance = battery.status === "maintenance";
  const supplyBonus = supplyRecoveryBonus(supplyStatus);
  const repairBonus = nearbyRepair ? 1.28 : 1;
  const readinessGain = deltaMs * (maintenance ? 0.00105 : 0.00028) * supplyBonus * repairBonus;
  const fatigueDrop = deltaMs * (maintenance ? 0.0012 : 0.00024) * supplyBonus * repairBonus;
  battery.readiness = clamp(battery.readiness + readinessGain, 8, 100);
  battery.fatigue = clamp(battery.fatigue - fatigueDrop, 0, 100);
  if (battery.status === "redeploying" && battery.cooldownMs <= 0) {
    battery.status = deriveUnitStatus({ ...battery, status: "ready" });
  } else if (!maintenance) {
    battery.status = deriveUnitStatus(battery);
  }
}

export function enterMaintenance(battery: DefenseBattery) {
  battery.status = "maintenance";
  battery.cooldownMs = Math.max(battery.cooldownMs, 8500);
  battery.lastAction = "maintenance";
  battery.daysSinceMaintenance = 0;
}

export function isMobileKind(kind: UnitKind) {
  return kind === "mobile" || kind === "short" || kind === "repair" || kind === "decoy";
}
