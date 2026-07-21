export const SHOW_LAUNCH_DEBUG = false;

// Fictional sector anchors for the game board. IDs, labels and centers do not
// represent sites, bases or operational routes; only broad approach semantics.
export const launchSectors = [
  { id: "north_corridor_a", name: "Північний сектор A", lat: 52.0, lng: 35.5, radiusKm: 90, weight: 4, threats: ["shahed", "gerbera", "parodiya"], role: "короткий північний дроновий підхід" },
  { id: "north_corridor_b", name: "Північний сектор B", lat: 53.0, lng: 33.5, radiusKm: 110, weight: 4, threats: ["shahed", "gerbera", "iskander_m", "s400_ballistic"], role: "змішаний північний підхід" },
  { id: "north_deep_a", name: "Далекий північний сектор", lat: 54.0, lng: 36.0, radiusKm: 130, weight: 3, threats: ["shahed", "gerbera", "parodiya"], role: "довгий північний дроновий коридор" },
  { id: "northwest_deep_a", name: "Північно-західний сектор", lat: 54.5, lng: 31.5, radiusKm: 140, weight: 2, threats: ["shahed", "gerbera", "parodiya"], role: "рідкісний довгий обхідний коридор" },
  { id: "east_tactical_a", name: "Східний тактичний сектор", lat: 50.5, lng: 37.0, radiusKm: 80, weight: 3, threats: ["s300_ballistic", "s400_ballistic", "iskander_m"], role: "короткий балістичний тиск" },
  { id: "east_deep_b", name: "Далекий східний сектор", lat: 52.0, lng: 39.5, radiusKm: 150, weight: 2, threats: ["iskander_m", "decoy_ballistic"], role: "далекий балістичний та імітаційний підхід" },
  { id: "southeast_corridor_a", name: "Південно-східний сектор A", lat: 49.0, lng: 40.5, radiusKm: 110, weight: 3, threats: ["shahed", "gerbera", "italmas", "parodiya"], role: "довгий східний дроновий підхід" },
  { id: "southeast_coastal_a", name: "Південно-східний прибережний сектор", lat: 47.0, lng: 39.0, radiusKm: 100, weight: 2, threats: ["shahed", "gerbera", "decoy"], role: "низьковисотний прибережний коридор" },
  { id: "southeast_corridor_b", name: "Південно-східний сектор B", lat: 46.0, lng: 38.5, radiusKm: 90, weight: 5, threats: ["shahed", "gerbera", "italmas", "parodiya"], role: "основний дроновий коридор" },
  { id: "southeast_corridor_c", name: "Південно-східний сектор C", lat: 46.5, lng: 37.5, radiusKm: 100, weight: 2, threats: ["shahed", "gerbera", "parodiya"], role: "додатковий дроновий коридор" },
  { id: "east_short_a", name: "Короткий східний сектор", lat: 48.0, lng: 38.0, radiusKm: 90, weight: 3, threats: ["shahed", "gerbera", "s300_ballistic", "decoy"], role: "короткий змішаний підхід" },
  { id: "south_land_a", name: "Південний сухопутний сектор", lat: 47.0, lng: 35.5, radiusKm: 110, weight: 2, threats: ["shahed", "gerbera", "kh59", "decoy"], role: "південний сухопутний коридор" },
  { id: "south_mixed_a", name: "Південний змішаний сектор", lat: 45.5, lng: 34.5, radiusKm: 90, weight: 3, threats: ["iskander_m", "s400_ballistic", "shahed"], role: "південний балістичний і змішаний підхід" },
  { id: "south_drone_a", name: "Південний дроновий сектор A", lat: 45.0, lng: 34.0, radiusKm: 80, weight: 4, threats: ["shahed", "gerbera", "parodiya"], role: "південний дроновий коридор" },
  { id: "south_drone_b", name: "Південний дроновий сектор B", lat: 45.0, lng: 36.0, radiusKm: 90, weight: 5, threats: ["shahed", "gerbera", "italmas", "parodiya"], role: "щільний південний дроновий коридор" },
  { id: "sea_corridor_a", name: "Морський сектор A", lat: 44.5, lng: 33.5, radiusKm: 130, weight: 2, threats: ["kalibr", "kh31p", "decoy_cruise"], role: "морський крилатий і support-підхід" },
  { id: "sea_corridor_b", name: "Морський сектор B", lat: 44.5, lng: 38.0, radiusKm: 150, weight: 2, threats: ["kalibr", "decoy_cruise"], role: "резервний морський коридор" },
  { id: "sea_corridor_c", name: "Відкритий морський сектор", lat: 43.5, lng: 32.5, radiusKm: 180, weight: 2, threats: ["kalibr", "kh31p"], role: "широка рандомізована морська зона" },
  { id: "long_range_air_a", name: "Далекий повітряний сектор A", lat: 46.0, lng: 47.5, radiusKm: 180, weight: 2, threats: ["kh101", "kh555", "decoy_cruise"], role: "далекий повітряний коридор" },
  { id: "long_range_air_b", name: "Далекий повітряний сектор B", lat: 44.5, lng: 46.5, radiusKm: 180, weight: 2, threats: ["kh101", "kh555", "decoy_cruise"], role: "південно-східний повітряний коридор" },
  { id: "long_range_air_c", name: "Далекий повітряний сектор C", lat: 58.5, lng: 39.5, radiusKm: 180, weight: 2, threats: ["kh101", "kh555"], role: "північний далекий повітряний коридор" },
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

export function launchSectorCenter(sector) {
  return { lat: sector.lat, lng: sector.lng };
}
