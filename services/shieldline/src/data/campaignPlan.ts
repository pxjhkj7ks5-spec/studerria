import type { CampaignState, CampaignTutorialAction, Coordinates, ThreatKind, UnitKind } from "../types/game";

export type CampaignPriority = "low" | "medium" | "high" | "veryHigh" | "critical";

export interface CampaignRouteTemplate {
  id: string;
  launchSector: "N1" | "NE1" | "NW1" | "E1" | "SE1" | "S1" | "SW1";
  preferredLaunchSectorIds?: string[];
  primaryRegion: string;
  targetCityId: string;
  allowedThreats: ThreatKind[];
  ballistic: boolean;
  baseWaypoints: Coordinates[];
  diversionChance: number;
  mergeCompatible: string[];
  difficultyWeight: number;
}

export interface CampaignWaveDefinition {
  timeSeconds: number;
  threatKind: ThreatKind;
  count: number;
  routeIds: string[];
  groupSize: number;
  mergeBehavior: string;
  targetRegion: string;
  diversionRatio: number;
  spawnSpreadSec: number;
  priority: CampaignPriority;
}

export interface CampaignMissionDefinition {
  id: string;
  index: number;
  title: string;
  durationMinutes: number;
  focusRegion: string;
  grant: number;
  objective: string;
  expectedThreatClasses: string[];
  broadAzimuth: string;
  attackRegionHint: string;
  briefing?: string;
  waves: CampaignWaveDefinition[];
  unlocks: UnitKind[];
}

const P = (lat: number, lng: number): Coordinates => ({ lat, lng });

// Deliberately broad, fictionalized corridors. They describe game sectors rather
// than real sites, addresses, or operational positions.
export const campaignRouteTemplates: CampaignRouteTemplate[] = [
  { id: "R01", launchSector: "N1", primaryRegion: "Столичний кластер", targetCityId: "kyiv", allowedThreats: ["parodiya", "gerbera", "geran2", "recon"], ballistic: false, baseWaypoints: [P(53.1, 30.2), P(51.8, 30.4), P(50.9, 30.2), P(50.45, 30.52)], diversionChance: .10, mergeCompatible: ["R02", "R03", "R29"], difficultyWeight: 1 },
  { id: "R02", launchSector: "NE1", primaryRegion: "Столичний кластер", targetCityId: "kyiv", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(52.6, 35.2), P(51.6, 33.4), P(50.8, 31.7), P(50.45, 30.52)], diversionChance: .15, mergeCompatible: ["R01", "R06", "R17"], difficultyWeight: 1 },
  { id: "R03", launchSector: "NW1", primaryRegion: "Столичний кластер", targetCityId: "kyiv", allowedThreats: ["parodiya", "gerbera", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(52.7, 27.0), P(51.3, 27.1), P(50.6, 28.7), P(50.45, 30.52)], diversionChance: .20, mergeCompatible: ["R01", "R18"], difficultyWeight: 2 },
  { id: "R04", launchSector: "E1", primaryRegion: "Північно-східний прикордонний кластер", targetCityId: "kharkiv", allowedThreats: ["parodiya", "gerbera", "geran2", "kh101", "kalibr", "recon"], ballistic: false, baseWaypoints: [P(50.5, 39.2), P(50.3, 37.6), P(49.99, 36.23)], diversionChance: .08, mergeCompatible: ["R05", "R16"], difficultyWeight: 2 },
  { id: "R05", launchSector: "E1", primaryRegion: "Північно-східний прикордонний кластер", targetCityId: "kharkiv", allowedThreats: ["parodiya", "gerbera", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(49.0, 40.1), P(48.9, 37.8), P(50.4, 37.2), P(49.99, 36.23)], diversionChance: .10, mergeCompatible: ["R04", "R16", "R22"], difficultyWeight: 2 },
  { id: "R06", launchSector: "NE1", primaryRegion: "Центральний енергетичний пояс", targetCityId: "cherkasy", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(52.3, 35.8), P(51.2, 33.7), P(49.9, 32.8), P(49.44, 32.06)], diversionChance: .20, mergeCompatible: ["R02", "R17", "R22"], difficultyWeight: 2 },
  { id: "R07", launchSector: "SE1", primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["gerbera", "geran2", "parodiya", "recon"], ballistic: false, baseWaypoints: [P(46.9, 39.7), P(47.5, 37.3), P(48.0, 35.7), P(48.46, 35.05)], diversionChance: .10, mergeCompatible: ["R08", "R09", "R21"], difficultyWeight: 2 },
  { id: "R08", launchSector: "SE1", primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["gerbera", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(45.7, 38.6), P(46.4, 36.1), P(47.2, 34.3), P(48.46, 35.05)], diversionChance: .12, mergeCompatible: ["R07", "R09", "R25"], difficultyWeight: 3 },
  { id: "R09", launchSector: "E1", primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["gerbera", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(49.1, 40.0), P(49.5, 37.8), P(49.1, 36.1), P(48.46, 35.05)], diversionChance: .10, mergeCompatible: ["R07", "R08", "R20"], difficultyWeight: 2 },
  { id: "R10", launchSector: "S1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["parodiya", "gerbera", "geran2", "recon"], ballistic: false, baseWaypoints: [P(42.8, 32.5), P(44.4, 31.0), P(45.46, 30.73)], diversionChance: .12, mergeCompatible: ["R11", "R13", "R15"], difficultyWeight: 1 },
  { id: "R11", launchSector: "S1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(43.0, 29.0), P(44.0, 28.7), P(45.0, 29.8), P(45.46, 30.73)], diversionChance: .10, mergeCompatible: ["R10", "R13", "R23"], difficultyWeight: 2 },
  { id: "R12", launchSector: "SE1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["geran2"], ballistic: false, baseWaypoints: [P(45.0, 38.5), P(46.4, 35.9), P(46.8, 33.1), P(45.46, 30.73)], diversionChance: .18, mergeCompatible: ["R10", "R15", "R19"], difficultyWeight: 2 },
  { id: "R13", launchSector: "S1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["gerbera", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(42.9, 34.6), P(44.2, 33.2), P(45.2, 31.8), P(45.46, 30.73)], diversionChance: .08, mergeCompatible: ["R10", "R11", "R23"], difficultyWeight: 2 },
  { id: "R14", launchSector: "S1", primaryRegion: "Західний логістичний кластер", targetCityId: "vinnytsia", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(42.8, 32.0), P(44.5, 31.7), P(47.0, 30.2), P(49.23, 28.47)], diversionChance: .45, mergeCompatible: ["R19", "R30"], difficultyWeight: 3 },
  { id: "R15", launchSector: "SE1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(45.1, 39.0), P(46.8, 36.0), P(47.0, 33.3), P(45.46, 30.73)], diversionChance: .15, mergeCompatible: ["R10", "R12", "R19"], difficultyWeight: 2 },
  { id: "R16", launchSector: "E1", primaryRegion: "Центральний енергетичний пояс", targetCityId: "cherkasy", allowedThreats: ["geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(49.6, 40.2), P(50.4, 37.5), P(50.0, 34.5), P(49.44, 32.06)], diversionChance: .18, mergeCompatible: ["R04", "R05", "R22"], difficultyWeight: 3 },
  { id: "R17", launchSector: "NE1", primaryRegion: "Центральний резервний кластер", targetCityId: "poltava", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(52.4, 36.2), P(51.1, 35.2), P(49.59, 34.55)], diversionChance: .35, mergeCompatible: ["R02", "R06", "R22"], difficultyWeight: 2 },
  { id: "R18", launchSector: "NW1", primaryRegion: "Західний логістичний кластер", targetCityId: "vinnytsia", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(52.6, 26.5), P(51.2, 25.5), P(50.0, 26.3), P(49.23, 28.47)], diversionChance: .30, mergeCompatible: ["R03", "R19"], difficultyWeight: 2 },
  { id: "R19", launchSector: "SW1", primaryRegion: "Західний логістичний кластер", targetCityId: "vinnytsia", allowedThreats: ["geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(46.3, 24.0), P(47.5, 25.7), P(49.23, 28.47)], diversionChance: .20, mergeCompatible: ["R12", "R14", "R15", "R18"], difficultyWeight: 3 },
  { id: "R20", launchSector: "E1", primaryRegion: "Столичний кластер", targetCityId: "kyiv", allowedThreats: ["parodiya", "geran2", "kh101", "kalibr", "jammer", "low-signature-cruise"], ballistic: false, baseWaypoints: [P(49.2, 40.3), P(49.0, 36.8), P(49.7, 33.4), P(50.45, 30.52)], diversionChance: .12, mergeCompatible: ["R09", "R16", "R22"], difficultyWeight: 4 },
  { id: "R21", launchSector: "SE1", primaryRegion: "Центральний резервний кластер", targetCityId: "poltava", allowedThreats: ["parodiya", "gerbera", "geran2", "recon"], ballistic: false, baseWaypoints: [P(46.2, 39.0), P(47.2, 37.0), P(48.4, 35.7), P(49.59, 34.55)], diversionChance: .25, mergeCompatible: ["R07", "R08", "R25"], difficultyWeight: 3 },
  { id: "R22", launchSector: "NE1", primaryRegion: "Центральний енергетичний пояс", targetCityId: "cherkasy", allowedThreats: ["geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(52.2, 36.2), P(51.0, 35.1), P(50.1, 33.5), P(49.44, 32.06)], diversionChance: .18, mergeCompatible: ["R05", "R06", "R16", "R17"], difficultyWeight: 3 },
  { id: "R23", launchSector: "S1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["kh101", "kalibr"], ballistic: false, baseWaypoints: [P(41.8, 34.5), P(42.7, 29.0), P(44.5, 28.7), P(45.46, 30.73)], diversionChance: .05, mergeCompatible: ["R11", "R13"], difficultyWeight: 4 },
  { id: "R24", launchSector: "E1", primaryRegion: "Північно-східний прикордонний кластер", targetCityId: "kharkiv", allowedThreats: ["kh101", "kalibr", "jammer"], ballistic: false, baseWaypoints: [P(49.4, 41.0), P(48.6, 38.7), P(49.4, 37.3), P(49.99, 36.23)], diversionChance: .08, mergeCompatible: ["R04", "R05"], difficultyWeight: 4 },
  { id: "R25", launchSector: "SE1", primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["kh101", "kalibr", "jammer", "low-signature-cruise"], ballistic: false, baseWaypoints: [P(45.6, 39.2), P(46.1, 36.5), P(47.1, 34.3), P(48.46, 35.05)], diversionChance: .07, mergeCompatible: ["R08", "R21"], difficultyWeight: 4 },
  { id: "R26", launchSector: "E1", primaryRegion: "Північно-східний прикордонний кластер", targetCityId: "kharkiv", allowedThreats: ["iskander"], ballistic: true, baseWaypoints: [P(50.4, 39.0), P(49.99, 36.23)], diversionChance: 0, mergeCompatible: [], difficultyWeight: 5 },
  { id: "R27", launchSector: "S1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["iskander"], ballistic: true, baseWaypoints: [P(43.2, 33.8), P(45.46, 30.73)], diversionChance: 0, mergeCompatible: [], difficultyWeight: 5 },
  { id: "R28", launchSector: "SE1", primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["iskander"], ballistic: true, baseWaypoints: [P(46.8, 39.1), P(48.46, 35.05)], diversionChance: 0, mergeCompatible: [], difficultyWeight: 5 },
  { id: "R29", launchSector: "N1", primaryRegion: "Центральний енергетичний пояс", targetCityId: "cherkasy", allowedThreats: ["parodiya", "gerbera", "recon"], ballistic: false, baseWaypoints: [P(53.0, 30.6), P(51.4, 30.5), P(50.6, 31.0), P(49.44, 32.06)], diversionChance: .60, mergeCompatible: ["R01", "R06"], difficultyWeight: 2 },
  { id: "R30", launchSector: "S1", primaryRegion: "Південний портовий / тиловий diversion", targetCityId: "kropyvnytskyi", allowedThreats: ["parodiya", "gerbera"], ballistic: false, baseWaypoints: [P(42.8, 33.2), P(45.4, 31.1), P(46.6, 32.5), P(48.51, 32.26)], diversionChance: .55, mergeCompatible: ["R14", "R15"], difficultyWeight: 2 },
  { id: "R31", launchSector: "SE1", preferredLaunchSectorIds: ["long_range_air_a"], primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["kh101", "low-signature-cruise"], ballistic: false, baseWaypoints: [P(46.4, 48.0), P(46.0, 43.4), P(47.2, 39.2), P(47.7, 36.8), P(48.46, 35.05)], diversionChance: .04, mergeCompatible: ["R25"], difficultyWeight: 4 },
  { id: "R32", launchSector: "SE1", preferredLaunchSectorIds: ["long_range_air_b"], primaryRegion: "Столичний кластер", targetCityId: "kyiv", allowedThreats: ["kh101"], ballistic: false, baseWaypoints: [P(44.8, 47.2), P(45.8, 42.5), P(47.5, 38.0), P(49.2, 34.0), P(50.45, 30.52)], diversionChance: .05, mergeCompatible: ["R20", "R35"], difficultyWeight: 5 },
  { id: "R33", launchSector: "S1", preferredLaunchSectorIds: ["sea_corridor_c"], primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["kalibr"], ballistic: false, baseWaypoints: [P(43.9, 32.8), P(44.3, 31.6), P(44.8, 30.5), P(45.46, 30.73)], diversionChance: .03, mergeCompatible: ["R23", "R34"], difficultyWeight: 4 },
  { id: "R34", launchSector: "S1", preferredLaunchSectorIds: ["sea_corridor_b"], primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["kalibr"], ballistic: false, baseWaypoints: [P(44.7, 37.8), P(44.1, 35.3), P(44.5, 32.7), P(45.46, 30.73)], diversionChance: .04, mergeCompatible: ["R13", "R33"], difficultyWeight: 4 },
  { id: "R35", launchSector: "E1", preferredLaunchSectorIds: ["long_range_air_a"], primaryRegion: "Столичний кластер", targetCityId: "kyiv", allowedThreats: ["kh101", "jammer", "low-signature-cruise"], ballistic: false, baseWaypoints: [P(46.4, 48.0), P(48.0, 43.2), P(49.0, 38.7), P(49.7, 34.2), P(50.45, 30.52)], diversionChance: .05, mergeCompatible: ["R20", "R32"], difficultyWeight: 5 },
  { id: "R36", launchSector: "S1", preferredLaunchSectorIds: ["sea_corridor_c", "sea_corridor_b"], primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["kalibr"], ballistic: false, baseWaypoints: [P(43.9, 34.0), P(45.0, 34.1), P(46.2, 34.0), P(47.3, 34.2), P(48.46, 35.05)], diversionChance: .04, mergeCompatible: ["R25"], difficultyWeight: 5 },
];

const w = (time: string, threatKind: ThreatKind, count: number, routeIds: string[], groupSize: number, mergeBehavior: string, targetRegion: string, diversionRatio: number, spawnSpreadSec: number, priority: CampaignPriority): CampaignWaveDefinition => {
  const [minutes, seconds] = time.split(":").map(Number);
  return { timeSeconds: minutes * 60 + seconds, threatKind, count, routeIds, groupSize, mergeBehavior, targetRegion, diversionRatio, spawnSpreadSec, priority };
};

export const campaignMissionsPlan: CampaignMissionDefinition[] = [
  { id: "first-contact", index: 1, title: "Перший контакт", durationMinutes: 10, focusRegion: "Столичний кластер", grant: 24, objective: "Розгорнути захист Києва, пройти бойове злагодження й відбити стислу комбіновану атаку.", expectedThreatClasses: ["Decoy", "Gerbera", "Shahed", "Cruise"], broadAzimuth: "Курський, Брянський і Каспійський напрямки", attackRegionHint: "Основний ризик — Київ і столичний кластер. Можливі відволікання в напрямку Черкас та західних підступів до столиці.", briefing: "Розвідка очікує атаку на Київ цієї ночі. Штаб передав навчальний комплект: розгорніть дальній радар і мобільну вогневу групу, перевірте розвідку та план, після чого одразу переходьте до бою.", unlocks: ["small-radar", "radar", "long-radar", "mvg", "manpads", "ew"], waves: [
    w("00:10", "parodiya", 2, ["R01", "R29"], 2, "splitFeint", "Столичний / енергетичний", .5, 4, "low"),
    w("00:45", "gerbera", 2, ["R02", "R03"], 2, "twoAxisScreen", "Столичний кластер", .25, 4, "low"),
    w("01:30", "geran2", 3, ["R01", "R02"], 3, "softMerge", "Столичний кластер", 0, 8, "medium"),
    w("02:25", "parodiya", 2, ["R03", "R29"], 2, "splitFeint", "Столичний / енергетичний", .5, 4, "low"),
    w("03:20", "geran2", 3, ["R02", "R06"], 3, "rallyMerge", "Столичний кластер", 0, 8, "high"),
    w("04:35", "kh101", 1, ["R32"], 1, "independent", "Столичний кластер", 0, 0, "veryHigh"),
    w("05:35", "gerbera", 2, ["R01", "R03"], 2, "crossingScreen", "Столичний кластер", .25, 5, "low"),
    w("06:30", "geran2", 4, ["R01", "R02"], 4, "hardMerge", "Столичний кластер", 0, 12, "high"),
    w("07:35", "geran2", 4, ["R02", "R03"], 4, "fullGroup", "Столичний кластер", 0, 12, "critical"),
  ] },
  { id: "southern-corridor", index: 2, title: "Південний маневр", durationMinutes: 22, focusRegion: "Південний портовий кластер", grant: 16, objective: "Передислокувати збережену мережу до Одеси, витримати морські коридори й зустріти перший балістичний фінал.", expectedThreatClasses: ["Recon", "Decoy", "Gerbera", "Shahed", "Cruise", "Ballistic"], broadAzimuth: "Чорне море, Крим, Приазов’я і південний балістичний напрямок", attackRegionHint: "Основний удар очікується по Одесі та південному узбережжю. Частина хибних цілей може піти через центральний тиловий коридор.", briefing: "Після оборони Києва противник переносить тиск на Одесу та морську логістику. На початку місії штаб безкоштовно передає радар середньої дальності. Перемістіть наявну мережу, підготуйте катер і Gepard проти дронів та збережіть С-300 для двох морських ракет і фінального швидкісного контакту.", unlocks: ["boat", "gepard"], waves: [
    w("00:45", "recon", 1, ["R10"], 1, "independent", "Портовий", 0, 0, "medium"),
    w("02:00", "gerbera", 4, ["R10", "R30"], 2, "twoAxisScreen", "Портовий / тиловий", .25, 35, "low"),
    w("04:00", "parodiya", 5, ["R10", "R14"], 2, "splitFeint", "Портовий / логістичний", .4, 40, "low"),
    w("06:00", "geran2", 4, ["R12", "R15"], 2, "corridorMerge", "Портовий", 0, 35, "medium"),
    w("08:30", "gerbera", 4, ["R13", "R30"], 2, "screenForNext", "Портовий / тиловий", .25, 30, "low"),
    w("09:00", "geran2", 5, ["R10", "R12"], 3, "rallyMerge", "Портовий", 0, 40, "high"),
    w("12:00", "kalibr", 1, ["R33"], 1, "independent", "Портовий", 0, 0, "veryHigh"),
    w("14:00", "parodiya", 3, ["R14", "R30"], 1, "diversionOnly", "Логістичний / тиловий", 1, 30, "low"),
    w("14:30", "geran2", 6, ["R11", "R15"], 3, "corridorMerge", "Портовий", .15, 45, "high"),
    w("18:00", "kalibr", 1, ["R34"], 1, "independent", "Портовий", 0, 0, "veryHigh"),
    w("18:20", "geran2", 7, ["R13", "R15"], 4, "hardMerge", "Портовий", 0, 45, "critical"),
    w("21:00", "iskander", 1, ["R27"], 1, "independent", "Портовий", 0, 0, "critical"),
  ] },
  { id: "eastern-arc", index: 3, title: "Сліпа зона", durationMinutes: 28, focusRegion: "Східний промисловий і центральний резервний кластери", grant: 24, objective: "Зберегти сенсорну мережу під розвідкою та перешкодами, відсіяти малопомітну ціль і пережити балістичний фінал.", expectedThreatClasses: ["Recon", "Jammer", "Decoy", "Shahed", "Low-signature cruise", "Cruise", "Ballistic"], broadAzimuth: "Ростовський, Приазовський, морський і балістичний напрямки", attackRegionHint: "Найвищий ризик — Дніпро й Полтава. Окремі ракетні контакти можуть зміщуватися до Харківського напрямку.", briefing: "Противник шукає сліпі зони навколо Дніпра й Полтави. Розвіддрон підвищить тиск наступних хвиль, постановник перешкод погіршить роботу сенсорів, а малопомітна ракета перевірить, чи правильно рознесені радари.", unlocks: ["long-radar", "buk", "s300"], waves: [
    w("00:45", "recon", 1, ["R21"], 1, "independent", "Центральний резерв", 0, 0, "medium"),
    w("02:00", "parodiya", 5, ["R07", "R21"], 3, "splitIntoTwoArcs", "Промисловий / резерв", .4, 35, "low"),
    w("04:00", "geran2", 6, ["R07", "R09"], 3, "rallyMerge", "Промисловий", 0, 40, "medium"),
    w("06:30", "gerbera", 4, ["R08"], 2, "screenForNext", "Промисловий", 0, 25, "low"),
    w("07:00", "geran2", 5, ["R08"], 3, "trailScreen", "Промисловий", 0, 30, "medium"),
    w("09:30", "jammer", 1, ["R24"], 1, "escort", "Прикордонний", 0, 0, "veryHigh"),
    w("10:00", "geran2", 8, ["R07", "R08"], 4, "corridorMerge", "Промисловий", .1, 50, "high"),
    w("13:30", "low-signature-cruise", 1, ["R31"], 1, "independent", "Промисловий", 0, 0, "veryHigh"),
    w("15:00", "parodiya", 5, ["R21", "R20"], 3, "falseCommit", "Резерв / столичний", .5, 35, "low"),
    w("15:30", "geran2", 8, ["R07", "R09"], 4, "hardMerge", "Промисловий", 0, 45, "high"),
    w("19:00", "kalibr", 1, ["R36"], 1, "independent", "Промисловий", 0, 0, "veryHigh"),
    w("21:00", "gerbera", 3, ["R09"], 3, "leadScreen", "Промисловий", 0, 20, "low"),
    w("21:30", "geran2", 8, ["R08"], 8, "fullGroup", "Промисловий", 0, 40, "critical"),
    w("24:30", "kh101", 2, ["R24", "R31"], 1, "independent", "Прикордонний / промисловий", .5, 20, "veryHigh"),
    w("27:00", "iskander", 1, ["R28"], 1, "independent", "Промисловий", 0, 0, "critical"),
  ] },
  { id: "saturation", index: 4, title: "Розірване небо", durationMinutes: 34, focusRegion: "Харківський, Дніпровський і Полтавський кластери", grant: 32, objective: "Розділити мережу між двома театрами, зберегти мобільний резерв і витримати дві частково синхронні кульмінації.", expectedThreatClasses: ["Recon", "Jammer", "Decoy", "Gerbera", "Shahed", "Low-signature cruise", "Cruise", "Ballistic"], broadAzimuth: "Бєлгородський, Ростовський, Приазовський і морський напрямки", attackRegionHint: "Очікується одночасний тиск на Харків, Дніпро та Полтаву. Один резерв варто залишити між східним і центральним секторами.", briefing: "Небо розривається між Харковом, Дніпром і Полтавою. Розвідка та перешкоди відкривають два театри одночасно; IRIS-T і NASAMS мають посилити середній ешелон, поки мобільний резерв закриває напрямок наступної хвилі.", unlocks: ["iris-t", "nasams"], waves: [
    w("00:45", "recon", 2, ["R04", "R07"], 1, "splitProbe", "Прикордонний / промисловий", .5, 20, "medium"),
    w("02:00", "parodiya", 8, ["R04", "R05"], 4, "mirrorRoutes", "Прикордонний", 0, 45, "low"),
    w("04:30", "geran2", 6, ["R04"], 6, "fullGroup", "Прикордонний", 0, 35, "medium"),
    w("07:30", "gerbera", 5, ["R07", "R21"], 3, "splitScreen", "Промисловий / резерв", .4, 35, "low"),
    w("08:00", "geran2", 6, ["R07", "R09"], 3, "rallyMerge", "Промисловий", 0, 40, "high"),
    w("10:30", "jammer", 2, ["R24", "R25"], 1, "dualEscort", "Прикордонний / промисловий", .5, 20, "veryHigh"),
    w("11:00", "geran2", 8, ["R04", "R07"], 4, "twoTheaterPressure", "Прикордонний / промисловий", .25, 50, "high"),
    w("14:30", "kh101", 2, ["R24", "R31"], 1, "staggeredIndependent", "Прикордонний / промисловий", .5, 20, "veryHigh"),
    w("17:00", "parodiya", 10, ["R05", "R21"], 5, "frontClutter", "Прикордонний / резерв", .3, 45, "low"),
    w("17:30", "geran2", 10, ["R05", "R08"], 5, "followClutter", "Прикордонний / промисловий", .2, 55, "high"),
    w("21:30", "iskander", 1, ["R26"], 1, "independent", "Прикордонний", 0, 0, "critical"),
    w("24:00", "geran2", 7, ["R07", "R09"], 4, "corridorMerge", "Промисловий", 0, 45, "high"),
    w("27:00", "low-signature-cruise", 1, ["R25"], 1, "independent", "Промисловий", 0, 0, "veryHigh"),
    w("27:20", "geran2", 8, ["R04", "R05"], 4, "hardMerge", "Прикордонний", 0, 45, "critical"),
    w("31:30", "kalibr", 1, ["R36"], 1, "independent", "Промисловий", 0, 0, "veryHigh"),
    w("31:50", "iskander", 1, ["R28"], 1, "independent", "Промисловий", 0, 0, "critical"),
  ] },
  { id: "mass-night", index: 5, title: "Масована ніч", durationMinutes: 42, focusRegion: "Столичний, центральний і західний кластери", grant: 45, objective: "Застосувати всю зароблену мережу у трьох актах фінальної атаки та зберегти верхній ешелон для подвійного ракетного фіналу.", expectedThreatClasses: ["Recon", "Jammer", "Decoy", "Gerbera", "Shahed", "Low-signature cruise", "Cruise", "Ballistic"], broadAzimuth: "усі основні пускові напрямки", attackRegionHint: "Головна ціль — Київ. Реальні відволікання очікуються в центральному й західному секторах, тому не стягуйте всю мережу до столиці.", briefing: "Фінальна ніч повертає кампанію до Києва, але противник відволікає мережу на центральні та західні маршрути. Спочатку прийдуть розвідка й РЕП, потім маса дронів із крилатими ракетами, а завершиться операція подвійним ракетним ударом. Patriot доступний для придбання, але його треба заслужити попередніми місіями.", unlocks: ["patriot"], waves: [
    w("00:45", "recon", 2, ["R01", "R29"], 1, "splitProbe", "Столичний / енергетичний", .5, 20, "medium"),
    w("02:00", "parodiya", 8, ["R01", "R29"], 4, "splitFeint", "Столичний / енергетичний", .3, 45, "low"),
    w("04:30", "geran2", 8, ["R02", "R03"], 4, "softMerge", "Столичний", 0, 50, "medium"),
    w("08:00", "jammer", 1, ["R35"], 1, "escort", "Столичний", 0, 0, "veryHigh"),
    w("08:30", "geran2", 8, ["R01", "R02"], 4, "rallyMerge", "Столичний", 0, 50, "high"),
    w("11:30", "gerbera", 6, ["R29", "R18"], 3, "frontClutter", "Енергетичний / логістичний", .4, 45, "low"),
    w("12:00", "geran2", 10, ["R02", "R20"], 5, "followClutter", "Столичний / енергетичний", .2, 55, "high"),
    w("16:00", "kh101", 2, ["R32", "R35"], 1, "staggeredIndependent", "Столичний", 0, 20, "veryHigh"),
    w("19:00", "parodiya", 7, ["R03", "R18"], 4, "falseCommit", "Столичний / логістичний", .4, 45, "low"),
    w("19:30", "geran2", 10, ["R01", "R22"], 5, "twoAxisPressure", "Столичний / енергетичний", .2, 55, "high"),
    w("23:00", "low-signature-cruise", 1, ["R20"], 1, "independent", "Столичний", 0, 0, "veryHigh"),
    w("25:00", "jammer", 2, ["R20", "R24"], 1, "dualEscort", "Столичний / прикордонний", .5, 20, "veryHigh"),
    w("25:30", "geran2", 12, ["R01", "R02", "R18"], 6, "mainCorridorPlusDiversion", "Столичний / логістичний", .25, 65, "critical"),
    w("29:30", "kh101", 3, ["R03", "R20", "R24"], 1, "staggeredIndependent", "Столичний / енергетичний / прикордонний", .33, 25, "veryHigh"),
    w("33:00", "geran2", 10, ["R01"], 10, "singleRouteTrail", "Столичний", 0, 55, "critical"),
    w("36:00", "iskander", 1, ["R26"], 1, "independent", "Столичний кластер", 0, 0, "critical"),
    w("36:00", "kh101", 2, ["R20", "R03"], 1, "independent", "Столичний кластер", 0, 10, "veryHigh"),
    w("38:30", "low-signature-cruise", 1, ["R35"], 1, "independent", "Столичний", 0, 0, "veryHigh"),
    w("39:00", "geran2", 8, ["R01", "R02"], 8, "terminalMass", "Столичний", .1, 50, "critical"),
    w("41:00", "iskander", 1, ["R26"], 1, "independent", "Столичний кластер", 0, 0, "critical"),
  ] },
];

export const campaignKillRewards: Partial<Record<ThreatKind, number>> = { parodiya: 1, decoy: 1, gerbera: 2, geran2: 2, drone: 2, recon: 4, kh101: 10, kalibr: 10, cruise: 10, jammer: 12, "low-signature-cruise": 14, iskander: 20, ballistic: 20 };

export const CAMPAIGN_TUTORIAL_COOLDOWN_MS = 5_000;
export const CAMPAIGN_TUTORIAL_ASSET_ACTION = "tutorial asset awaiting deployment";
export const CAMPAIGN_REINFORCEMENT_ACTION = "reinforcement awaiting deployment";

export const campaignTutorialSteps: Array<{
  action: CampaignTutorialAction;
  panelTarget?: "units" | "planning" | "intel";
  title: string;
  body: string;
}> = [
  { action: "open-intel", panelTarget: "intel", title: "Розвідка: атака на Київ", body: "Очікується повітряна атака на столицю. Відкрийте «Розвідку» та прийміть оперативне зведення." },
  { action: "inspect-ammo-depot", title: "Склад БК: поповнення батарей", body: "Натисніть ангар на заході України. Він поповнює резерв батарей, але пошкодження сповільнює виробництво, а знищення забирає половину накопиченого БК." },
  { action: "open-units", panelTarget: "units", title: "Підготуйте сенсорну мережу", body: "Відкрийте «ППО». Навчальний дальній радар уже передано на склад." },
  { action: "place-long-radar-near-kyiv", panelTarget: "units", title: "Розгорніть дальній радар", body: "Виберіть складський дальній радар і встановіть його поблизу Києва, але не в межах міста." },
  { action: "place-mvg-east-of-kyiv", panelTarget: "units", title: "Додайте вогневий ешелон", body: "Тепер виберіть складську МВГ. Рекомендована позиція — східніше Києва, на маршруті повільних дронів." },
  { action: "purchase-depot-mvg", panelTarget: "units", title: "Придбайте охорону складу", body: "Придбайте ще одну МВГ за 6 млн ₴. Вона стане окремим ближнім захистом ангара БК." },
  { action: "place-mvg-near-depot", panelTarget: "units", title: "Прикрийте склад БК", body: "Поставте придбану МВГ так, щоб ангар перебував у її внутрішній зоні 9 км." },
  { action: "open-planning", panelTarget: "planning", title: "Підтвердьте план оборони", body: "Відкрийте «План». Після перевірки розпочнеться короткий відлік до реального бою." },
];

export function settleCampaignTutorial(campaign: CampaignState, nowMs: number) {
  if (campaign.missionIndex !== 1 || campaign.tutorialStep >= campaignTutorialSteps.length || nowMs < campaign.tutorialNextPromptAtMs) return false;
  const expectedAction = campaignTutorialSteps[campaign.tutorialStep].action;
  const queuedIndex = campaign.tutorialActionQueue.indexOf(expectedAction);
  if (queuedIndex < 0) return false;
  campaign.tutorialActionQueue.splice(queuedIndex, 1);
  campaign.tutorialStep += 1;
  campaign.tutorialNextPromptAtMs = nowMs + CAMPAIGN_TUTORIAL_COOLDOWN_MS;
  return true;
}

export function recordCampaignTutorialAction(campaign: CampaignState | null | undefined, action: CampaignTutorialAction, nowMs: number) {
  if (!campaign || campaign.missionIndex !== 1 || campaign.tutorialStep >= campaignTutorialSteps.length) return false;
  if (!campaign.tutorialActionQueue.includes(action)) campaign.tutorialActionQueue.push(action);
  return settleCampaignTutorial(campaign, nowMs);
}

export function campaignTutorialComplete(campaign: CampaignState | null | undefined) {
  return Boolean(campaign && campaign.missionIndex === 1 && campaign.tutorialStep >= campaignTutorialSteps.length);
}

export function activeCampaignTutorialCue(campaign: CampaignState | null | undefined, nowMs: number) {
  if (!campaign || campaign.missionIndex !== 1 || campaignTutorialComplete(campaign) || nowMs < campaign.tutorialNextPromptAtMs) return null;
  return campaignTutorialSteps[campaign.tutorialStep] || null;
}

export function campaignTutorialPlacementAction(kind: UnitKind): CampaignTutorialAction | null {
  if (kind === "long-radar") return "place-long-radar-near-kyiv";
  if (kind === "mvg") return "place-mvg-east-of-kyiv";
  return null;
}

export function isFreeCampaignDeploymentAction(lastAction: string) {
  return lastAction === CAMPAIGN_TUTORIAL_ASSET_ACTION || lastAction === CAMPAIGN_REINFORCEMENT_ACTION;
}

export function getCampaignMission(index: number) { return campaignMissionsPlan[Math.max(0, Math.min(campaignMissionsPlan.length - 1, index - 1))]; }
export function getCampaignRoute(id: string) { return campaignRouteTemplates.find((route) => route.id === id); }
export function missionTargetCount(mission: CampaignMissionDefinition) { return mission.waves.reduce((sum, wave) => sum + wave.count, 0); }
