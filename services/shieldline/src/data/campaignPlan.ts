import type { Coordinates, ThreatKind, UnitKind } from "../types/game";

export type CampaignPriority = "low" | "medium" | "high" | "veryHigh" | "critical";

export interface CampaignRouteTemplate {
  id: string;
  launchSector: "N1" | "NE1" | "NW1" | "E1" | "SE1" | "S1" | "SW1";
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
  rewardCap: number;
  objective: string;
  expectedThreatClasses: string[];
  broadAzimuth: string;
  waves: CampaignWaveDefinition[];
  unlocks: UnitKind[];
}

const P = (lat: number, lng: number): Coordinates => ({ lat, lng });

// Deliberately broad, fictionalized corridors. They describe game sectors rather
// than real sites, addresses, or operational positions.
export const campaignRouteTemplates: CampaignRouteTemplate[] = [
  { id: "R01", launchSector: "N1", primaryRegion: "Столичний кластер", targetCityId: "kyiv", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(53.1, 30.2), P(51.8, 30.4), P(50.9, 30.2), P(50.45, 30.52)], diversionChance: .10, mergeCompatible: ["R02", "R03", "R29"], difficultyWeight: 1 },
  { id: "R02", launchSector: "NE1", primaryRegion: "Столичний кластер", targetCityId: "kyiv", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(52.6, 35.2), P(51.6, 33.4), P(50.8, 31.7), P(50.45, 30.52)], diversionChance: .15, mergeCompatible: ["R01", "R06", "R17"], difficultyWeight: 1 },
  { id: "R03", launchSector: "NW1", primaryRegion: "Столичний кластер", targetCityId: "kyiv", allowedThreats: ["parodiya", "gerbera", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(52.7, 27.0), P(51.3, 27.1), P(50.6, 28.7), P(50.45, 30.52)], diversionChance: .20, mergeCompatible: ["R01", "R18"], difficultyWeight: 2 },
  { id: "R04", launchSector: "E1", primaryRegion: "Північно-східний прикордонний кластер", targetCityId: "kharkiv", allowedThreats: ["parodiya", "gerbera", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(50.5, 39.2), P(50.3, 37.6), P(49.99, 36.23)], diversionChance: .08, mergeCompatible: ["R05", "R16"], difficultyWeight: 2 },
  { id: "R05", launchSector: "E1", primaryRegion: "Північно-східний прикордонний кластер", targetCityId: "kharkiv", allowedThreats: ["parodiya", "gerbera", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(49.0, 40.1), P(48.9, 37.8), P(50.4, 37.2), P(49.99, 36.23)], diversionChance: .10, mergeCompatible: ["R04", "R16", "R22"], difficultyWeight: 2 },
  { id: "R06", launchSector: "NE1", primaryRegion: "Центральний енергетичний пояс", targetCityId: "cherkasy", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(52.3, 35.8), P(51.2, 33.7), P(49.9, 32.8), P(49.44, 32.06)], diversionChance: .20, mergeCompatible: ["R02", "R17", "R22"], difficultyWeight: 2 },
  { id: "R07", launchSector: "SE1", primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["gerbera", "geran2", "parodiya"], ballistic: false, baseWaypoints: [P(46.9, 39.7), P(47.5, 37.3), P(48.0, 35.7), P(48.46, 35.05)], diversionChance: .10, mergeCompatible: ["R08", "R09", "R21"], difficultyWeight: 2 },
  { id: "R08", launchSector: "SE1", primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["gerbera", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(45.7, 38.6), P(46.4, 36.1), P(47.2, 34.3), P(48.46, 35.05)], diversionChance: .12, mergeCompatible: ["R07", "R09", "R25"], difficultyWeight: 3 },
  { id: "R09", launchSector: "E1", primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["gerbera", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(49.1, 40.0), P(49.5, 37.8), P(49.1, 36.1), P(48.46, 35.05)], diversionChance: .10, mergeCompatible: ["R07", "R08", "R20"], difficultyWeight: 2 },
  { id: "R10", launchSector: "S1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(42.8, 32.5), P(44.4, 31.0), P(45.46, 30.73)], diversionChance: .12, mergeCompatible: ["R11", "R13", "R15"], difficultyWeight: 1 },
  { id: "R11", launchSector: "S1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(43.0, 29.0), P(44.0, 28.7), P(45.0, 29.8), P(45.46, 30.73)], diversionChance: .10, mergeCompatible: ["R10", "R13", "R23"], difficultyWeight: 2 },
  { id: "R12", launchSector: "SE1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["geran2"], ballistic: false, baseWaypoints: [P(45.0, 38.5), P(46.4, 35.9), P(46.8, 33.1), P(45.46, 30.73)], diversionChance: .18, mergeCompatible: ["R10", "R15", "R19"], difficultyWeight: 2 },
  { id: "R13", launchSector: "S1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["gerbera", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(42.9, 34.6), P(44.2, 33.2), P(45.2, 31.8), P(45.46, 30.73)], diversionChance: .08, mergeCompatible: ["R10", "R11", "R23"], difficultyWeight: 2 },
  { id: "R14", launchSector: "S1", primaryRegion: "Західний логістичний кластер", targetCityId: "vinnytsia", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(42.8, 32.0), P(44.5, 31.7), P(47.0, 30.2), P(49.23, 28.47)], diversionChance: .45, mergeCompatible: ["R19", "R30"], difficultyWeight: 3 },
  { id: "R15", launchSector: "SE1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(45.1, 39.0), P(46.8, 36.0), P(47.0, 33.3), P(45.46, 30.73)], diversionChance: .15, mergeCompatible: ["R10", "R12", "R19"], difficultyWeight: 2 },
  { id: "R16", launchSector: "E1", primaryRegion: "Центральний енергетичний пояс", targetCityId: "cherkasy", allowedThreats: ["geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(49.6, 40.2), P(50.4, 37.5), P(50.0, 34.5), P(49.44, 32.06)], diversionChance: .18, mergeCompatible: ["R04", "R05", "R22"], difficultyWeight: 3 },
  { id: "R17", launchSector: "NE1", primaryRegion: "Центральний резервний кластер", targetCityId: "poltava", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(52.4, 36.2), P(51.1, 35.2), P(49.59, 34.55)], diversionChance: .35, mergeCompatible: ["R02", "R06", "R22"], difficultyWeight: 2 },
  { id: "R18", launchSector: "NW1", primaryRegion: "Західний логістичний кластер", targetCityId: "vinnytsia", allowedThreats: ["parodiya", "gerbera", "geran2"], ballistic: false, baseWaypoints: [P(52.6, 26.5), P(51.2, 25.5), P(50.0, 26.3), P(49.23, 28.47)], diversionChance: .30, mergeCompatible: ["R03", "R19"], difficultyWeight: 2 },
  { id: "R19", launchSector: "SW1", primaryRegion: "Західний логістичний кластер", targetCityId: "vinnytsia", allowedThreats: ["geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(46.3, 24.0), P(47.5, 25.7), P(49.23, 28.47)], diversionChance: .20, mergeCompatible: ["R12", "R14", "R15", "R18"], difficultyWeight: 3 },
  { id: "R20", launchSector: "E1", primaryRegion: "Столичний кластер", targetCityId: "kyiv", allowedThreats: ["parodiya", "geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(49.2, 40.3), P(49.0, 36.8), P(49.7, 33.4), P(50.45, 30.52)], diversionChance: .12, mergeCompatible: ["R09", "R16", "R22"], difficultyWeight: 4 },
  { id: "R21", launchSector: "SE1", primaryRegion: "Центральний резервний кластер", targetCityId: "poltava", allowedThreats: ["parodiya", "geran2"], ballistic: false, baseWaypoints: [P(46.2, 39.0), P(47.2, 37.0), P(48.4, 35.7), P(49.59, 34.55)], diversionChance: .25, mergeCompatible: ["R07", "R08", "R25"], difficultyWeight: 3 },
  { id: "R22", launchSector: "NE1", primaryRegion: "Центральний енергетичний пояс", targetCityId: "cherkasy", allowedThreats: ["geran2", "kh101", "kalibr"], ballistic: false, baseWaypoints: [P(52.2, 36.2), P(51.0, 35.1), P(50.1, 33.5), P(49.44, 32.06)], diversionChance: .18, mergeCompatible: ["R05", "R06", "R16", "R17"], difficultyWeight: 3 },
  { id: "R23", launchSector: "S1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["kh101", "kalibr"], ballistic: false, baseWaypoints: [P(41.8, 34.5), P(42.7, 29.0), P(44.5, 28.7), P(45.46, 30.73)], diversionChance: .05, mergeCompatible: ["R11", "R13"], difficultyWeight: 4 },
  { id: "R24", launchSector: "E1", primaryRegion: "Північно-східний прикордонний кластер", targetCityId: "kharkiv", allowedThreats: ["kh101", "kalibr"], ballistic: false, baseWaypoints: [P(49.4, 41.0), P(48.6, 38.7), P(49.4, 37.3), P(49.99, 36.23)], diversionChance: .08, mergeCompatible: ["R04", "R05"], difficultyWeight: 4 },
  { id: "R25", launchSector: "SE1", primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["kh101", "kalibr"], ballistic: false, baseWaypoints: [P(45.6, 39.2), P(46.1, 36.5), P(47.1, 34.3), P(48.46, 35.05)], diversionChance: .07, mergeCompatible: ["R08", "R21"], difficultyWeight: 4 },
  { id: "R26", launchSector: "E1", primaryRegion: "Північно-східний прикордонний кластер", targetCityId: "kharkiv", allowedThreats: ["iskander"], ballistic: true, baseWaypoints: [P(50.4, 39.0), P(49.99, 36.23)], diversionChance: 0, mergeCompatible: [], difficultyWeight: 5 },
  { id: "R27", launchSector: "S1", primaryRegion: "Південний портовий кластер", targetCityId: "odesa", allowedThreats: ["iskander"], ballistic: true, baseWaypoints: [P(43.2, 33.8), P(45.46, 30.73)], diversionChance: 0, mergeCompatible: [], difficultyWeight: 5 },
  { id: "R28", launchSector: "SE1", primaryRegion: "Східний промисловий кластер", targetCityId: "dnipro", allowedThreats: ["iskander"], ballistic: true, baseWaypoints: [P(46.8, 39.1), P(48.46, 35.05)], diversionChance: 0, mergeCompatible: [], difficultyWeight: 5 },
  { id: "R29", launchSector: "N1", primaryRegion: "Центральний енергетичний пояс", targetCityId: "cherkasy", allowedThreats: ["parodiya", "gerbera"], ballistic: false, baseWaypoints: [P(53.0, 30.6), P(51.4, 30.5), P(50.6, 31.0), P(49.44, 32.06)], diversionChance: .60, mergeCompatible: ["R01", "R06"], difficultyWeight: 2 },
  { id: "R30", launchSector: "S1", primaryRegion: "Південний портовий / тиловий diversion", targetCityId: "kropyvnytskyi", allowedThreats: ["parodiya", "gerbera"], ballistic: false, baseWaypoints: [P(42.8, 33.2), P(45.4, 31.1), P(46.6, 32.5), P(48.51, 32.26)], diversionChance: .55, mergeCompatible: ["R14", "R15"], difficultyWeight: 2 },
];

const w = (time: string, threatKind: ThreatKind, count: number, routeIds: string[], groupSize: number, mergeBehavior: string, targetRegion: string, diversionRatio: number, spawnSpreadSec: number, priority: CampaignPriority): CampaignWaveDefinition => {
  const [minutes, seconds] = time.split(":").map(Number);
  return { timeSeconds: minutes * 60 + seconds, threatKind, count, routeIds, groupSize, mergeBehavior, targetRegion, diversionRatio, spawnSpreadSec, priority };
};

export const campaignMissionsPlan: CampaignMissionDefinition[] = [
  { id: "first-contact", index: 1, title: "Перший контакт", durationMinutes: 15, focusRegion: "Столичний кластер", grant: 38, rewardCap: 18, objective: "Навчитися виявляти, класифікувати й пріоритезувати загрози без марної витрати дорогого БК.", expectedThreatClasses: ["Parody", "Gerbera", "Shahed"], broadAzimuth: "північ і північний схід", unlocks: ["radar", "mvg", "manpads"], waves: [
    w("00:45", "parodiya", 2, ["R01", "R29"], 2, "splitFeint", "Столичний / енергетичний", .5, 5, "low"),
    w("01:35", "gerbera", 2, ["R02", "R03"], 2, "twoAxisScreen", "Столичний кластер", .25, 5, "low"),
    w("02:30", "parodiya", 2, ["R01", "R29"], 2, "splitFeint", "Столичний / енергетичний", .5, 5, "low"),
    w("03:25", "gerbera", 2, ["R02", "R29"], 2, "crossingScreen", "Столичний / енергетичний", .25, 5, "low"),
    w("04:20", "parodiya", 2, ["R03", "R29"], 2, "splitFeint", "Столичний / енергетичний", .5, 5, "low"),
    w("05:15", "geran2", 2, ["R02", "R06"], 2, "softMerge", "Столичний кластер", 0, 5, "medium"),
    w("06:15", "parodiya", 2, ["R01", "R29"], 2, "splitFeint", "Столичний / енергетичний", .5, 5, "low"),
    w("07:10", "gerbera", 2, ["R02", "R03"], 2, "twoAxisScreen", "Столичний кластер", .25, 5, "low"),
    w("08:05", "parodiya", 2, ["R01", "R29"], 2, "splitFeint", "Столичний / енергетичний", .5, 5, "low"),
    w("09:00", "geran2", 2, ["R01", "R02"], 2, "softMerge", "Столичний кластер", 0, 5, "medium"),
    w("10:00", "parodiya", 2, ["R03", "R29"], 2, "splitFeint", "Столичний / енергетичний", .5, 5, "low"),
    w("11:00", "gerbera", 2, ["R02", "R06"], 2, "crossingScreen", "Столичний / енергетичний", .25, 5, "low"),
    w("12:00", "parodiya", 2, ["R01", "R29"], 2, "splitFeint", "Столичний / енергетичний", .5, 5, "low"),
    w("13:00", "geran2", 2, ["R01", "R02"], 2, "fullGroup", "Столичний кластер", 0, 5, "high"),
  ] },
  { id: "southern-corridor", index: 2, title: "Південний коридор", durationMinutes: 35, focusRegion: "Південний портовий кластер", grant: 32, rewardCap: 35, objective: "Передислокувати частину мережі на новий театр, не оголюючи попередній рубіж.", expectedThreatClasses: ["Decoy", "Shahed", "Cruise"], broadAzimuth: "морський південь і південний схід", unlocks: ["boat", "ew", "gepard", "drone-operators"], waves: [
    w("02:00", "gerbera", 4, ["R10", "R30"], 1, "none", "Портовий", .25, 70, "low"), w("06:00", "parodiya", 5, ["R10", "R14"], 2, "splitFeint", "Портовий / логістичний", .4, 60, "low"), w("11:00", "geran2", 4, ["R12", "R15"], 2, "rallyMerge", "Портовий", 0, 50, "medium"), w("15:30", "gerbera", 3, ["R13"], 3, "screenForNext", "Портовий", 0, 25, "low"), w("16:00", "geran2", 6, ["R10", "R12"], 3, "rallyMerge", "Портовий", 0, 55, "high"), w("21:30", "parodiya", 3, ["R14"], 1, "diversionOnly", "Логістичний", 1, 40, "low"), w("23:00", "kalibr", 1, ["R23"], 1, "independent", "Портовий", 0, 0, "veryHigh"), w("28:00", "geran2", 8, ["R11", "R15"], 5, "corridorMerge", "Портовий", .15, 65, "high"), w("32:30", "gerbera", 2, ["R30"], 1, "falseTerminal", "Південний вузол", 1, 20, "low"), w("33:00", "geran2", 5, ["R13"], 5, "fullGroup", "Портовий", 0, 30, "high"),
  ] },
  { id: "eastern-arc", index: 3, title: "Східна дуга", durationMinutes: 45, focusRegion: "Східний промисловий кластер", grant: 48, rewardCap: 55, objective: "Витримати щільні групи Shahed і перші повноцінні decoy + cruise оркестровки.", expectedThreatClasses: ["Decoy", "Shahed", "Cruise"], broadAzimuth: "схід і південний схід", unlocks: ["buk", "s300"], waves: [
    w("03:00", "parodiya", 6, ["R07", "R21"], 3, "splitIntoTwoArcs", "Промисловий / резерв", .33, 60, "low"), w("08:00", "geran2", 6, ["R07", "R09"], 3, "rallyMerge", "Промисловий", 0, 45, "medium"), w("13:30", "gerbera", 4, ["R08"], 2, "screenForCruise", "Промисловий", 0, 30, "low"), w("14:00", "geran2", 4, ["R08"], 2, "trailDecoys", "Промисловий", 0, 35, "medium"), w("20:00", "kalibr", 1, ["R25"], 1, "independent", "Промисловий", 0, 0, "veryHigh"), w("24:30", "parodiya", 4, ["R21", "R20"], 2, "falseCommit", "Резерв / столичний", .5, 45, "low"), w("25:00", "geran2", 10, ["R07", "R08"], 6, "corridorMerge", "Промисловий", .1, 80, "high"), w("31:00", "kh101", 2, ["R24", "R25"], 1, "independent", "Прикордонний / промисловий", .5, 20, "veryHigh"), w("36:30", "gerbera", 3, ["R09"], 3, "leadScreen", "Промисловий", 0, 25, "low"), w("37:00", "geran2", 10, ["R07", "R09"], 8, "hardMerge", "Промисловий", 0, 60, "high"), w("42:00", "geran2", 8, ["R08"], 8, "fullGroup", "Промисловий", 0, 35, "critical"),
  ] },
  { id: "saturation", index: 4, title: "Насичення", durationMinutes: 50, focusRegion: "Північно-східний прикордонний кластер", grant: 70, rewardCap: 80, objective: "Пережити перевантаження сенсорів і першу балістичну перевірку верхнього ешелону.", expectedThreatClasses: ["Decoy", "Shahed", "Cruise", "Ballistic"], broadAzimuth: "східний прикордонний сектор", unlocks: ["iris-t", "nasams"], waves: [
    w("02:00", "parodiya", 8, ["R04", "R05"], 4, "mirrorRoutes", "Прикордонний", 0, 70, "low"), w("07:00", "geran2", 6, ["R04"], 6, "fullGroup", "Прикордонний", 0, 40, "medium"), w("11:30", "gerbera", 5, ["R05"], 5, "screen", "Прикордонний", 0, 25, "low"), w("12:00", "geran2", 5, ["R05"], 5, "behindScreen", "Прикордонний", 0, 25, "high"), w("18:00", "iskander", 1, ["R26"], 1, "independent", "Прикордонний", 0, 0, "critical"), w("22:00", "geran2", 12, ["R04", "R05"], 8, "corridorMerge", "Прикордонний", .1, 75, "high"), w("28:30", "kh101", 2, ["R24"], 1, "staggeredIndependent", "Прикордонний", 0, 25, "veryHigh"), w("29:00", "geran2", 6, ["R16"], 3, "sideAxisPressure", "Енергетичний", 1, 55, "medium"), w("35:00", "geran2", 15, ["R04"], 15, "fullGroup", "Прикордонний", 0, 65, "critical"), w("41:30", "parodiya", 10, ["R05", "R17"], 5, "frontClutter", "Прикордонний / резерв", .3, 60, "low"), w("42:00", "geran2", 6, ["R05"], 6, "followClutter", "Прикордонний", 0, 30, "high"), w("47:00", "iskander", 1, ["R26"], 1, "independent", "Прикордонний", 0, 0, "critical"), w("47:20", "kalibr", 1, ["R24"], 1, "independent", "Прикордонний", 0, 0, "veryHigh"),
  ] },
  { id: "mass-night", index: 5, title: "Масована ніч", durationMinutes: 60, focusRegion: "Столичний кластер", grant: 100, rewardCap: 120, objective: "Застосувати всю збережену мережу, економіку, БК і передислокації у фінальній комбінованій атаці.", expectedThreatClasses: ["Decoy", "Shahed", "Cruise", "Ballistic"], broadAzimuth: "північ, північний схід і схід", unlocks: ["patriot"], waves: [
    w("03:00", "parodiya", 10, ["R01", "R29"], 5, "splitFeint", "Столичний / енергетичний", .3, 75, "low"), w("08:00", "geran2", 8, ["R02", "R03"], 3, "softMerge", "Столичний", 0, 60, "medium"), w("13:00", "geran2", 10, ["R01", "R02"], 5, "rallyMerge", "Столичний", 0, 70, "high"), w("18:00", "kh101", 2, ["R03", "R20"], 1, "independent", "Столичний / енергетичний", .25, 30, "veryHigh"), w("22:00", "geran2", 12, ["R01"], 12, "fullGroup", "Столичний", 0, 65, "critical"), w("27:30", "gerbera", 6, ["R29", "R18"], 3, "frontClutter", "Енергетичний / логістичний", .4, 60, "low"), w("28:00", "geran2", 8, ["R02", "R20"], 4, "followClutter", "Столичний / енергетичний", .2, 55, "high"), w("34:00", "iskander", 1, ["R26"], 1, "independent", "Столичний", 0, 0, "critical"), w("38:00", "geran2", 12, ["R01", "R02"], 6, "hardMerge", "Столичний", 0, 80, "critical"), w("44:00", "kh101", 3, ["R03", "R20", "R24"], 1, "staggeredIndependent", "Столичний / енергетичний / прикордонний", .33, 25, "veryHigh"), w("50:00", "geran2", 15, ["R01", "R02", "R18"], 12, "mainCorridorPlusDiversion", "Столичний / логістичний", .25, 90, "critical"), w("56:00", "iskander", 1, ["R26"], 1, "independent", "Столичний", 0, 0, "critical"), w("56:00", "kh101", 2, ["R20", "R03"], 1, "independent", "Столичний", 0, 10, "veryHigh"), w("56:20", "parodiya", 5, ["R29"], 4, "terminalNoise", "Енергетичний", 1, 45, "low"), w("56:40", "geran2", 8, ["R01", "R02"], 8, "terminalMass", "Столичний", .1, 75, "critical"),
  ] },
];

export const campaignKillRewards: Partial<Record<ThreatKind, number>> = { parodiya: 1, decoy: 1, gerbera: 2, geran2: 2, drone: 2, kh101: 10, kalibr: 10, cruise: 10, iskander: 20, ballistic: 20 };
export const campaignResupplyCosts: Partial<Record<UnitKind, number>> = { mvg: 1, boat: 1.4, manpads: 4, gepard: 2, "drone-operators": 4, buk: 12, s300: 16, "iris-t": 18, nasams: 16, patriot: 25 };
export const campaignRedeployRates: Record<UnitKind, number> = { mvg: .10, boat: .10, manpads: .10, gepard: .15, buk: .15, ew: .15, "drone-operators": .15, radar: .15, s300: .20, "iris-t": .20, nasams: .20, patriot: .25 };

export const campaignTutorialSteps = [
  { atSeconds: 5, durationSeconds: 7, panelTarget: "planning" as const, title: "Відкрийте «План»", body: "Перегляньте доступні дії перед першим контактом." },
  { atSeconds: 22, durationSeconds: 7, panelTarget: "intel" as const, title: "Відкрийте «Розвідку»", body: "Ознайомтеся з журналом контактів і напрямками пусків." },
  { atSeconds: 78, durationSeconds: 7, title: "Контакти низького пріоритету", body: "Не витрачайте дорогі ракети на кожну обманку." },
  { atSeconds: 92, durationSeconds: 7, title: "Читайте картку цілі", body: "Зіставляйте тип, швидкість, курс і достовірність." },
  { atSeconds: 390, durationSeconds: 7, title: "Реальна загроза", body: "Пріоритезуйте Shahed і збережіть БК для фіналу." },
  { atSeconds: 570, durationSeconds: 7, title: "Бережіть боєкомплект", body: "Після місії безкоштовно відновиться лише 25% комплекту." },
  { atSeconds: 690, durationSeconds: 7, title: "Частина цілей відволікає", body: "Тримайте головний театр прикритим." },
  { atSeconds: 810, durationSeconds: 7, title: "Кампанія має пам’ять", body: "Позиції, БК, стан систем, досвід, стійкість і гаманець перейдуть далі." },
];

export function activeCampaignTutorialCue(elapsedSeconds: number, visitedPanels: readonly string[] = []) {
  return campaignTutorialSteps.find((cue) => elapsedSeconds >= cue.atSeconds
    && elapsedSeconds < cue.atSeconds + cue.durationSeconds
    && (!("panelTarget" in cue) || typeof cue.panelTarget !== "string" || !visitedPanels.includes(cue.panelTarget))) || null;
}

export function getCampaignMission(index: number) { return campaignMissionsPlan[Math.max(0, Math.min(campaignMissionsPlan.length - 1, index - 1))]; }
export function getCampaignRoute(id: string) { return campaignRouteTemplates.find((route) => route.id === id); }
export function missionTargetCount(mission: CampaignMissionDefinition) { return mission.waves.reduce((sum, wave) => sum + wave.count, 0); }
