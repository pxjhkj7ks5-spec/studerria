export const SHOW_LAUNCH_DEBUG = false;

export const launchSectors = [
  { id: "kursk_north", name: "Курський напрямок", lat: 51.75, lng: 36.20, radiusKm: 45, weight: 4, threats: ["shahed", "gerbera", "parodiya"], role: "Північний дроновий вектор на Суми / Полтаву / Київ" },
  { id: "bryansk_north", name: "Брянський напрямок", lat: 53.25, lng: 34.35, radiusKm: 55, weight: 4, threats: ["shahed", "gerbera", "iskander_m", "s400_ballistic"], role: "Північний вектор на Чернігів / Київ / Житомир" },
  { id: "oryol_deep_north", name: "Орловський напрямок", lat: 52.95, lng: 36.05, radiusKm: 60, weight: 3, threats: ["shahed", "gerbera", "parodiya"], role: "Глибший північний старт, довші маршрути дронів" },
  { id: "smolensk_northwest", name: "Смоленський напрямок", lat: 54.30, lng: 32.45, radiusKm: 70, weight: 2, threats: ["shahed", "gerbera", "parodiya"], role: "Північно-західний вектор, рідший сценарій для різноманіття маршрутів" },
  { id: "belgorod_tactical", name: "Бєлгородський напрямок", lat: 50.60, lng: 36.60, radiusKm: 40, weight: 3, threats: ["s300_ballistic", "s400_ballistic", "iskander_m"], role: "Короткий балістичний тиск по Харкову / Сумщині" },
  { id: "voronezh_deep_east", name: "Воронезький напрямок", lat: 51.65, lng: 39.20, radiusKm: 80, weight: 2, threats: ["iskander_m", "decoy_ballistic"], role: "Глибший східний балістичний / імітаційний сектор" },
  { id: "millerovo_rostov", name: "Міллерово / Ростовський напрямок", lat: 48.90, lng: 40.40, radiusKm: 55, weight: 3, threats: ["shahed", "gerbera", "italmas", "parodiya"], role: "Східний дроновий вектор на Харків / Дніпро / центр" },
  { id: "taganrog_azov", name: "Таганрозько-Азовський сектор", lat: 47.20, lng: 38.90, radiusKm: 50, weight: 2, threats: ["shahed", "gerbera", "decoy"], role: "Південно-східний вектор через Азов / Донбас" },
  { id: "primorsko_akhtarsk", name: "Приморсько-Ахтарський напрямок", lat: 46.05, lng: 38.20, radiusKm: 45, weight: 5, threats: ["shahed", "gerbera", "italmas", "parodiya"], role: "Один з головних дронових векторів на південь / центр" },
  { id: "yeisk_kuban", name: "Єйсько-Кубанський сектор", lat: 46.70, lng: 38.30, radiusKm: 50, weight: 2, threats: ["shahed", "gerbera", "parodiya"], role: "Додатковий південний дроновий сектор" },
  { id: "occupied_donetsk", name: "Окупований Донецький напрямок", lat: 48.00, lng: 37.80, radiusKm: 45, weight: 3, threats: ["shahed", "gerbera", "s300_ballistic", "decoy"], role: "Коротші маршрути на схід / Дніпро / Запоріжжя" },
  { id: "occupied_azov", name: "Окупований Приазовський сектор", lat: 46.80, lng: 35.70, radiusKm: 55, weight: 2, threats: ["shahed", "gerbera", "kh59", "decoy"], role: "Південний вектор: Запоріжжя / Дніпро / Миколаїв" },
  { id: "dzhankoi_crimea", name: "Північний Крим / Джанкойський сектор", lat: 45.70, lng: 34.40, radiusKm: 45, weight: 3, threats: ["iskander_m", "s400_ballistic", "shahed"], role: "Кримський балістичний і змішаний сектор" },
  { id: "hvardiiske_crimea", name: "Гвардійське / центральний Крим", lat: 45.10, lng: 34.00, radiusKm: 40, weight: 4, threats: ["shahed", "gerbera", "parodiya"], role: "Кримський дроновий сектор на центр / південь" },
  { id: "chauda_crimea", name: "Мис Чауда / східний Крим", lat: 45.00, lng: 35.85, radiusKm: 45, weight: 5, threats: ["shahed", "gerbera", "italmas", "parodiya"], role: "Ключовий кримський дроновий сектор" },
  { id: "sevastopol_black_sea", name: "Севастопольсько-чорноморський сектор", lat: 44.60, lng: 33.50, radiusKm: 65, weight: 2, threats: ["kalibr", "kh31p", "decoy_cruise"], role: "Морські / протирадарні пуски, рідше ніж дрони" },
  { id: "novorossiysk_black_sea", name: "Новоросійський чорноморський сектор", lat: 44.70, lng: 37.80, radiusKm: 75, weight: 2, threats: ["kalibr", "decoy_cruise"], role: "Резервний морський сектор для Kalibr" },
  { id: "black_sea_launch_box", name: "Відкрите Чорне море", lat: 44.00, lng: 32.80, radiusKm: 120, weight: 2, threats: ["kalibr", "kh31p"], role: "Рандомізована морська launch box, не прив’язана до порту" },
  { id: "astrakhan_air_corridor", name: "Астраханський повітряний коридор", lat: 46.35, lng: 48.00, radiusKm: 150, weight: 2, threats: ["kh101", "kh555", "decoy_cruise"], role: "Далекий повітряний пуск стратегічної авіації" },
  { id: "caspian_air_corridor", name: "Каспійський повітряний коридор", lat: 44.80, lng: 47.20, radiusKm: 170, weight: 2, threats: ["kh101", "kh555", "decoy_cruise"], role: "Далекий південно-східний повітряний коридор" },
  { id: "vologda_air_corridor", name: "Вологодський повітряний коридор", lat: 59.20, lng: 39.90, radiusKm: 150, weight: 2, threats: ["kh101", "kh555"], role: "Північний далекий пуск Х-101 / Х-555" },
];

export const FIRST_NIGHT_LAUNCH_SECTOR_IDS = [
  "kursk_north",
  "bryansk_north",
  "millerovo_rostov",
  "primorsko_akhtarsk",
  "occupied_donetsk",
  "hvardiiske_crimea",
  "chauda_crimea",
  "belgorod_tactical",
];

export const SECOND_NIGHT_LAUNCH_SECTOR_IDS = [
  ...FIRST_NIGHT_LAUNCH_SECTOR_IDS,
  "occupied_azov",
  "dzhankoi_crimea",
  "sevastopol_black_sea",
  "novorossiysk_black_sea",
  "astrakhan_air_corridor",
  "caspian_air_corridor",
];

export const ALL_LAUNCH_SECTOR_IDS = launchSectors.map((sector) => sector.id);
export const CAMPAIGN_RANDOM_LAUNCH_SECTOR_IDS = [...ALL_LAUNCH_SECTOR_IDS];

const threatAliases = {
  drone: ["shahed", "gerbera", "italmas"],
  ballistic: ["s300_ballistic", "s400_ballistic", "iskander_m", "decoy_ballistic"],
  cruise: ["kalibr", "kh59", "kh31p", "kh101", "kh555", "decoy_cruise"],
  decoy: ["decoy", "parodiya", "decoy_ballistic", "decoy_cruise"],
  combined: ["shahed", "iskander_m", "kalibr", "kh101"],
  saturation: ["shahed", "gerbera", "italmas", "parodiya"],
  geran2: ["shahed"],
  gerbera: ["gerbera"],
  parodiya: ["parodiya"],
  kh101: ["kh101", "kh555"],
  kalibr: ["kalibr"],
  iskander: ["iskander_m"],
};

export function threatProfilesForKind(kind) {
  return threatAliases[kind] || [kind];
}

export function sectorSupportsThreat(sector, threatType) {
  if (!threatType) return true;
  return threatProfilesForKind(threatType).some((profile) => sector.threats.includes(profile));
}

export function createLaunchSectorState(ids) {
  const allowed = ids ? new Set(ids) : null;
  return launchSectors
    .filter((sector) => !allowed || allowed.has(sector.id))
    .map((sector) => ({ ...sector, threats: [...sector.threats], state: "idle" }));
}

export function pickWeightedSector(sectors, allowedThreatType = null, random = Math.random) {
  const compatible = sectors.filter((sector) => sectorSupportsThreat(sector, allowedThreatType));
  if (!compatible.length) throw new Error(`No launch sector supports threat type: ${allowedThreatType || "any"}`);
  const totalWeight = compatible.reduce((sum, sector) => sum + Math.max(0, Number(sector.weight) || 0), 0);
  if (totalWeight <= 0) return compatible[0];
  let cursor = Math.max(0, Math.min(0.999999999, random())) * totalWeight;
  for (const sector of compatible) {
    cursor -= Math.max(0, Number(sector.weight) || 0);
    if (cursor < 0) return sector;
  }
  return compatible.at(-1);
}

export function randomPointInSector(sector, random = Math.random) {
  const earthRadiusKm = 6371;
  const distanceKm = Math.sqrt(Math.max(0, Math.min(0.999999999, random()))) * sector.radiusKm;
  const bearing = Math.max(0, Math.min(0.999999999, random())) * Math.PI * 2;
  const angularDistance = distanceKm / earthRadiusKm;
  const lat1 = sector.lat * Math.PI / 180;
  const lng1 = sector.lng * Math.PI / 180;
  const lat2 = Math.asin(Math.sin(lat1) * Math.cos(angularDistance) + Math.cos(lat1) * Math.sin(angularDistance) * Math.cos(bearing));
  const lng2 = lng1 + Math.atan2(Math.sin(bearing) * Math.sin(angularDistance) * Math.cos(lat1), Math.cos(angularDistance) - Math.sin(lat1) * Math.sin(lat2));
  return {
    lat: lat2 * 180 / Math.PI,
    lng: ((lng2 * 180 / Math.PI + 540) % 360) - 180,
  };
}

export function generateLaunchOrigin(sectors, threatType, random = Math.random) {
  const sector = pickWeightedSector(sectors, threatType, random);
  const point = randomPointInSector(sector, random);
  if (SHOW_LAUNCH_DEBUG) console.debug("[Shieldline launch]", { threatType, sector: sector.id, point });
  return { sector, point };
}

export function launchSectorCategory(sector) {
  if (sector.threats.some((threat) => ["s300_ballistic", "s400_ballistic", "iskander_m", "decoy_ballistic"].includes(threat))) return "ballistic";
  if (sector.threats.some((threat) => ["kalibr", "kh31p", "kh59", "kh101", "kh555", "decoy_cruise"].includes(threat))) return "cruise";
  return "drone";
}

export function launchSectorCenter(sector) {
  return { lat: sector.lat, lng: sector.lng };
}
