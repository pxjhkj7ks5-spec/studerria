export const GUIDED_THREE_STAGE_PROFILE = "guided-three-stage";

export const launchSectorIdsByDirection = {
  north: ["kursk_north", "bryansk_north", "oryol_deep_north", "smolensk_northwest", "vologda_air_corridor"],
  east: ["belgorod_tactical", "voronezh_deep_east", "millerovo_rostov", "taganrog_azov", "occupied_donetsk", "astrakhan_air_corridor"],
  south: ["primorsko_akhtarsk", "yeisk_kuban", "occupied_azov", "dzhankoi_crimea", "hvardiiske_crimea", "chauda_crimea", "sevastopol_black_sea", "novorossiysk_black_sea", "black_sea_launch_box"],
};

const droneKinds = ["geran2", "gerbera", "parodiya"];
const targetSectors = ["north", "south", "east", "west", "hq"];

function pick(values, random) {
  return values[Math.min(values.length - 1, Math.floor(random() * values.length))];
}

export function shuffleLaunchDirections(random = Math.random) {
  const directions = ["north", "east", "south"];
  for (let index = directions.length - 1; index > 0; index -= 1) {
    const other = Math.floor(random() * (index + 1));
    [directions[index], directions[other]] = [directions[other], directions[index]];
  }
  return directions;
}

export function cruiseKindForDirection(direction) {
  return direction === "south" ? "kalibr" : "kh101";
}

export function guidedThreatKind(stageIndex, launchIndex, direction, random = Math.random) {
  if (stageIndex === 0) return pick(droneKinds, random);
  if (stageIndex === 1) {
    if (launchIndex === 0) return cruiseKindForDirection(direction);
    return random() < 0.5 ? pick(droneKinds, random) : cruiseKindForDirection(direction);
  }
  return launchIndex === 0 ? cruiseKindForDirection(direction) : "iskander";
}

export function guidedStageLaunchCount(stageIndex) {
  return stageIndex < 2 ? 3 : 2;
}

export function guidedStageForElapsed(elapsedMs) {
  if (elapsedMs < 60_000) return 0;
  if (elapsedMs < 120_000) return 1;
  if (elapsedMs < 160_000) return 2;
  return 3;
}

export function nextGuidedLaunchDelayMs(random = Math.random) {
  return 16_000 + Math.round(random() * 8_000);
}

export function createGuidedCampaignSchedule(startedAtMs, random = Math.random) {
  return {
    profile: GUIDED_THREE_STAGE_PROFILE,
    directions: shuffleLaunchDirections(random),
    stageIndex: 0,
    stageLaunchCount: 0,
    nextLaunchAtMs: startedAtMs + 10_000,
    ballisticLaunched: false,
  };
}

export function createGuidedOperationWaves(random = Math.random) {
  const directions = shuffleLaunchDirections(random);
  const waves = [];
  let etaSeconds = 10;
  for (let stageIndex = 0; stageIndex < 3; stageIndex += 1) {
    etaSeconds = Math.max(etaSeconds, stageIndex === 0 ? 10 : stageIndex * 60);
    const direction = directions[stageIndex];
    const launchCount = guidedStageLaunchCount(stageIndex);
    for (let launchIndex = 0; launchIndex < launchCount; launchIndex += 1) {
      const threatKind = guidedThreatKind(stageIndex, launchIndex, direction, random);
      waves.push({
        id: `wave-${String(waves.length + 1).padStart(2, "0")}`,
        index: waves.length + 1,
        threatKind,
        originSector: direction,
        launchDirection: direction,
        targetSector: pick(targetSectors, random),
        etaSeconds,
        size: 1,
        difficulty: 34 + stageIndex * 8 + Math.round(random() * 8),
      });
      if (threatKind === "iskander") return waves;
      if (launchIndex < launchCount - 1) etaSeconds += Math.round(nextGuidedLaunchDelayMs(random) / 1000);
    }
  }
  return waves;
}

export function sectorIdsForDirection(direction) {
  return launchSectorIdsByDirection[direction] || [];
}
