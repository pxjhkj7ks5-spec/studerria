export const SHOW_LAUNCH_DEBUG = false;

// Geographic names identify broad launch directions. The centers and radii
// remain game abstractions and do not represent exact sites or routes.
export const launchSectors = [
  { id: "north_corridor_a", name: "Курський напрямок", lat: 52.0, lng: 35.5, radiusKm: 90, weight: 4, threats: ["shahed", "gerbera", "parodiya"], role: "Північний напрямок на Суми, Полтаву та Київ" },
  { id: "north_corridor_b", name: "Брянський напрямок", lat: 53.0, lng: 33.5, radiusKm: 110, weight: 4, threats: ["shahed", "gerbera", "iskander_m", "s400_ballistic"], role: "Північний напрямок на Чернігів, Київ та Житомир" },
  { id: "north_deep_a", name: "Орловський напрямок", lat: 54.0, lng: 36.0, radiusKm: 130, weight: 3, threats: ["shahed", "gerbera", "parodiya"], role: "Глибокий північний напрямок" },
  { id: "northwest_deep_a", name: "Смоленський напрямок", lat: 54.5, lng: 31.5, radiusKm: 140, weight: 2, threats: ["shahed", "gerbera", "parodiya"], role: "Північно-західний обхідний напрямок" },
  { id: "east_tactical_a", name: "Бєлгородський напрямок", lat: 50.5, lng: 37.0, radiusKm: 80, weight: 3, threats: ["s300_ballistic", "s400_ballistic", "iskander_m"], role: "Короткий напрямок на Харків і Сумщину" },
  { id: "east_deep_b", name: "Воронезький напрямок", lat: 52.0, lng: 39.5, radiusKm: 150, weight: 2, threats: ["iskander_m", "decoy_ballistic"], role: "Глибокий східний напрямок" },
  { id: "southeast_corridor_a", name: "Міллерово / Ростовський напрямок", lat: 49.0, lng: 40.5, radiusKm: 110, weight: 3, threats: ["shahed", "gerbera", "italmas", "parodiya"], role: "Східний напрямок на Харків, Дніпро та центр" },
  { id: "southeast_coastal_a", name: "Таганрозько-Азовський напрямок", lat: 47.0, lng: 39.0, radiusKm: 100, weight: 2, threats: ["shahed", "gerbera", "decoy"], role: "Південно-східний напрямок через Азов і Донбас" },
  { id: "southeast_corridor_b", name: "Приморсько-Ахтарський напрямок", lat: 46.0, lng: 38.5, radiusKm: 90, weight: 5, threats: ["shahed", "gerbera", "italmas", "parodiya"], role: "Основний південно-східний напрямок" },
  { id: "southeast_corridor_c", name: "Єйсько-Кубанський напрямок", lat: 46.5, lng: 37.5, radiusKm: 100, weight: 2, threats: ["shahed", "gerbera", "parodiya"], role: "Додатковий південний напрямок" },
  { id: "east_short_a", name: "Окупований Донецький напрямок", lat: 48.0, lng: 38.0, radiusKm: 90, weight: 3, threats: ["shahed", "gerbera", "s300_ballistic", "decoy"], role: "Короткий напрямок на схід, Дніпро та Запоріжжя" },
  { id: "south_land_a", name: "Окупований Приазовський напрямок", lat: 47.0, lng: 35.5, radiusKm: 110, weight: 2, threats: ["shahed", "gerbera", "kh59", "decoy"], role: "Південний напрямок на Запоріжжя, Дніпро та Миколаїв" },
  { id: "south_mixed_a", name: "Північний Крим / Джанкойський напрямок", lat: 45.5, lng: 34.5, radiusKm: 90, weight: 3, threats: ["iskander_m", "s400_ballistic", "shahed"], role: "Кримський змішаний напрямок" },
  { id: "south_drone_a", name: "Гвардійське / центральний Крим", lat: 45.0, lng: 34.0, radiusKm: 80, weight: 4, threats: ["shahed", "gerbera", "parodiya"], role: "Кримський напрямок на центр і південь" },
  { id: "south_drone_b", name: "Мис Чауда / східний Крим", lat: 45.0, lng: 36.0, radiusKm: 90, weight: 5, threats: ["shahed", "gerbera", "italmas", "parodiya"], role: "Ключовий кримський напрямок" },
  { id: "sea_corridor_a", name: "Севастопольсько-чорноморський напрямок", lat: 44.5, lng: 33.5, radiusKm: 130, weight: 2, threats: ["kalibr", "kh31p", "decoy_cruise"], role: "Морський напрямок із Чорного моря" },
  { id: "sea_corridor_b", name: "Новоросійський чорноморський напрямок", lat: 44.5, lng: 38.0, radiusKm: 150, weight: 2, threats: ["kalibr", "decoy_cruise"], role: "Східний морський напрямок" },
  { id: "sea_corridor_c", name: "Відкрите Чорне море", lat: 43.5, lng: 32.5, radiusKm: 180, weight: 2, threats: ["kalibr", "kh31p"], role: "Широка морська зона пусків" },
  { id: "long_range_air_a", name: "Астраханський повітряний напрямок", lat: 46.0, lng: 47.5, radiusKm: 180, weight: 2, threats: ["kh101", "kh555", "decoy_cruise"], role: "Далекий напрямок стратегічної авіації" },
  { id: "long_range_air_b", name: "Каспійський повітряний напрямок", lat: 44.5, lng: 46.5, radiusKm: 180, weight: 2, threats: ["kh101", "kh555", "decoy_cruise"], role: "Далекий південно-східний повітряний напрямок" },
  { id: "long_range_air_c", name: "Вологодський повітряний напрямок", lat: 58.5, lng: 39.5, radiusKm: 180, weight: 2, threats: ["kh101", "kh555"], role: "Північний далекий повітряний напрямок" },
];

export const FIRST_NIGHT_LAUNCH_SECTOR_IDS = [
  "north_corridor_a",
  "north_corridor_b",
  "southeast_corridor_a",
  "southeast_corridor_b",
  "east_short_a",
  "south_drone_a",
  "south_drone_b",
  "east_tactical_a",
];

export const SECOND_NIGHT_LAUNCH_SECTOR_IDS = [
  ...FIRST_NIGHT_LAUNCH_SECTOR_IDS,
  "south_land_a",
  "south_mixed_a",
  "sea_corridor_a",
  "sea_corridor_b",
  "long_range_air_a",
  "long_range_air_b",
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
  recon: ["shahed", "gerbera", "italmas"],
  "low-signature-cruise": ["kh59", "kh31p", "decoy_cruise"],
  jammer: ["kh31p", "decoy_cruise"],
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

export function launchSectorThreatClasses(sector) {
  const classes = [];
  if (sector.threats.some((threat) => ["s300_ballistic", "s400_ballistic", "iskander_m", "decoy_ballistic"].includes(threat))) classes.push("Балістичні ракети");
  if (sector.threats.some((threat) => ["kalibr", "kh31p", "kh59", "kh101", "kh555", "decoy_cruise"].includes(threat))) classes.push("Крилаті ракети");
  if (sector.threats.some((threat) => ["shahed", "gerbera", "italmas", "parodiya", "decoy"].includes(threat))) classes.push("Дрони");
  return classes;
}

export function launchSectorCenter(sector) {
  return { lat: sector.lat, lng: sector.lng };
}
