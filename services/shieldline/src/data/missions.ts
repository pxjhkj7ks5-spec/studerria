import type { MissionDefinition, SectorId } from "../domain/contracts";
import { campaignMissionsPlan } from "./campaignPlan";

function originSector(routeId: string): SectorId {
  if (["R10", "R11", "R13", "R14", "R23", "R27", "R30"].includes(routeId)) return "south";
  if (["R03", "R18", "R19"].includes(routeId)) return "west";
  if (["R01", "R02", "R06", "R17", "R22", "R29"].includes(routeId)) return "north";
  return "east";
}

export const campaignMissions: MissionDefinition[] = campaignMissionsPlan.map((mission) => ({
  id: mission.id,
  modeId: "campaign",
  title: mission.title,
  subtitle: `Кампанія · Місія ${mission.index} з 5`,
  durationMinutes: mission.durationMinutes,
  difficulty: mission.index === 1 ? "guided" : mission.index < 4 ? "standard" : mission.index === 4 ? "hard" : "expert",
  resources: { budget: mission.grant, ammo: 0, morale: 100, energy: 100 },
  grant: mission.grant,
  focusRegion: mission.focusRegion,
  expectedThreatClasses: mission.expectedThreatClasses,
  broadAzimuth: mission.broadAzimuth,
  mainRisk: mission.expectedThreatClasses.join(" + "),
  victoryCondition: mission.objective,
  briefing: `${mission.focusRegion}. ${mission.objective}`,
  waves: mission.waves.map((wave, waveIndex) => ({
    id: `${mission.id}-wave-${String(waveIndex + 1).padStart(2, "0")}`,
    index: waveIndex + 1,
    threatKind: wave.threatKind,
    originSector: originSector(wave.routeIds[0]),
    targetSector: "hq",
    etaSeconds: wave.timeSeconds,
    size: wave.count,
    difficulty: 30 + mission.index * 8,
    routeIds: wave.routeIds,
    groupSize: wave.groupSize,
    // The deterministic server adapter consumes one neutral authored value.
    // Rich merge behaviour stays in the live campaign director, which owns it.
    mergeBehavior: "authored",
    targetRegion: wave.targetRegion,
    diversionRatio: wave.diversionRatio,
    spawnSpreadSec: wave.spawnSpreadSec,
    priority: wave.priority,
  })),
}));
