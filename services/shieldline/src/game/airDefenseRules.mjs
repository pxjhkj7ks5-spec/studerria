const DRONES = ["drone", "saturation", "geran2", "gerbera", "recon"];
const DECOYS = ["decoy", "parodiya"];
const CRUISE = ["cruise", "combined", "kh101", "kalibr", "low-signature-cruise"];
const BALLISTIC = ["ballistic", "iskander"];
const SUPPORT = ["jammer"];
const ALL_THREATS = [...DRONES, ...DECOYS, ...CRUISE, ...BALLISTIC, ...SUPPORT];

const doctrine = (values = {}) => ({
  allowedTargets: [], preferredTargets: [], reservedFor: [], forbiddenByDefault: [],
  minConfidenceToEngage: 35, minTrackQuality: 40, conserveAmmoThreshold: 0.25,
  allowManualOverride: true, salvoPolicy: "single", cheapFirstPolicy: false,
  networkRequired: true, coastalOnly: false, ...values,
});

export const AIR_DEFENSE_RULES_VERSION = "3.0.0";

export const UNIT_RULES = Object.freeze({
  "small-radar": { roleClass: "sensor", reserve: 0, sensor: { acquisitionBase: 88, classificationGain: 12, fusionValue: 2, lowSignaturePenalty: 13 }, doctrine: doctrine({ networkRequired: false, allowManualOverride: false }) },
  radar: { roleClass: "sensor", reserve: 0, sensor: { acquisitionBase: 90, classificationGain: 9, fusionValue: 7, lowSignaturePenalty: 9 }, doctrine: doctrine({ networkRequired: false, allowManualOverride: false }) },
  "long-radar": { roleClass: "sensor", reserve: 0, sensor: { acquisitionBase: 84, classificationGain: 6, fusionValue: 13, lowSignaturePenalty: 17 }, doctrine: doctrine({ networkRequired: false, allowManualOverride: false }) },
  mvg: { roleClass: "gun", reserve: 10, sensor: { acquisitionBase: 46, classificationGain: 4, fusionValue: 0, lowSignaturePenalty: 18 }, doctrine: doctrine({ allowedTargets: [...DRONES, ...DECOYS], preferredTargets: ["recon", "geran2", "gerbera", "drone", "saturation"], forbiddenByDefault: [...CRUISE, ...BALLISTIC, ...SUPPORT], minConfidenceToEngage: 30, minTrackQuality: 34, conserveAmmoThreshold: 0.2, networkRequired: false }) },
  boat: { roleClass: "specialist", reserve: 12, sensor: { acquisitionBase: 56, classificationGain: 5, fusionValue: 0, lowSignaturePenalty: 13 }, doctrine: doctrine({ allowedTargets: [...DRONES, ...DECOYS, "kalibr", "low-signature-cruise"], preferredTargets: ["recon", "geran2", "gerbera", "kalibr"], forbiddenByDefault: [...BALLISTIC, "kh101", "cruise", "combined", ...SUPPORT], minConfidenceToEngage: 30, minTrackQuality: 32, conserveAmmoThreshold: 0.2, networkRequired: false, coastalOnly: true }) },
  ew: { roleClass: "ew", reserve: "infinite", doctrine: doctrine({ allowedTargets: [...DRONES, ...DECOYS, ...CRUISE, ...SUPPORT], preferredTargets: ["jammer", "parodiya", "decoy", "gerbera", "recon", "geran2"], forbiddenByDefault: [...BALLISTIC], minConfidenceToEngage: 22, minTrackQuality: 26, conserveAmmoThreshold: 0, allowManualOverride: false, networkRequired: false }) },
  manpads: { roleClass: "shorad", reserve: 6, sensor: { acquisitionBase: 36, classificationGain: 3, fusionValue: 0, lowSignaturePenalty: 20 }, doctrine: doctrine({ allowedTargets: [...DRONES, "cruise", "kh101", "kalibr", "low-signature-cruise"], preferredTargets: ["recon", "geran2", "drone", "kh101", "kalibr"], forbiddenByDefault: [...DECOYS, ...BALLISTIC, ...SUPPORT], minConfidenceToEngage: 48, minTrackQuality: 48, conserveAmmoThreshold: 0.34, networkRequired: false }) },
  gepard: { roleClass: "shorad", reserve: 16, sensor: { acquisitionBase: 50, classificationGain: 4, fusionValue: 0, lowSignaturePenalty: 17 }, doctrine: doctrine({ allowedTargets: [...DRONES, ...DECOYS], preferredTargets: ["recon", "saturation", "geran2", "gerbera"], forbiddenByDefault: [...CRUISE, ...BALLISTIC, ...SUPPORT], minConfidenceToEngage: 30, minTrackQuality: 34, conserveAmmoThreshold: 0.18, networkRequired: false }) },
  buk: { roleClass: "mrad", reserve: 8, doctrine: doctrine({ allowedTargets: [...CRUISE, "geran2", "jammer"], preferredTargets: ["jammer", "low-signature-cruise", "kh101", "kalibr", "cruise"], reservedFor: [...CRUISE, "jammer"], forbiddenByDefault: [...DECOYS, "gerbera", "drone", "saturation", "recon", ...BALLISTIC], minConfidenceToEngage: 58, minTrackQuality: 58, conserveAmmoThreshold: 0.5, cheapFirstPolicy: true }) },
  s300: { roleClass: "area-defense", reserve: 8, doctrine: doctrine({ allowedTargets: [...CRUISE, ...BALLISTIC], preferredTargets: [...CRUISE, ...BALLISTIC], reservedFor: [...CRUISE, ...BALLISTIC], forbiddenByDefault: [...DRONES, ...DECOYS, ...SUPPORT], minConfidenceToEngage: 62, minTrackQuality: 62, conserveAmmoThreshold: 0.5, cheapFirstPolicy: true }) },
  "iris-t": { roleClass: "mrad", reserve: 8, doctrine: doctrine({ allowedTargets: [...CRUISE, ...DRONES, "jammer"], preferredTargets: ["jammer", "low-signature-cruise", "kh101", "kalibr", "cruise", "geran2"], reservedFor: [...CRUISE, "jammer"], forbiddenByDefault: [...DECOYS, "gerbera", "drone", "saturation", "recon", ...BALLISTIC], minConfidenceToEngage: 60, minTrackQuality: 62, conserveAmmoThreshold: 0.5, cheapFirstPolicy: true }) },
  nasams: { roleClass: "mrad", reserve: 12, doctrine: doctrine({ allowedTargets: [...CRUISE, ...DRONES, "jammer"], preferredTargets: ["jammer", "low-signature-cruise", "kh101", "kalibr", "cruise", "geran2"], reservedFor: [...CRUISE, "jammer"], forbiddenByDefault: [...DECOYS, "gerbera", "drone", "saturation", "recon", ...BALLISTIC], minConfidenceToEngage: 58, minTrackQuality: 60, conserveAmmoThreshold: 0.42, cheapFirstPolicy: true }) },
  patriot: { roleClass: "upper-tier", reserve: 4, doctrine: doctrine({ allowedTargets: [...BALLISTIC, ...CRUISE], preferredTargets: ["iskander", "ballistic", "kh101"], reservedFor: [...BALLISTIC], forbiddenByDefault: [...DRONES, ...DECOYS], minConfidenceToEngage: 72, minTrackQuality: 74, conserveAmmoThreshold: 0.75, salvoPolicy: "conditional-double" }) },
  "drone-operators": { roleClass: "specialist", reserve: 12, sensor: { acquisitionBase: 42, classificationGain: 4, fusionValue: 0, lowSignaturePenalty: 18 }, doctrine: doctrine({ allowedTargets: [...DRONES, ...DECOYS], preferredTargets: ["gerbera", "parodiya", "geran2"], forbiddenByDefault: [...CRUISE, ...BALLISTIC], minConfidenceToEngage: 42, minTrackQuality: 44, conserveAmmoThreshold: 0.25, networkRequired: false }) },
});

const threat = (values) => ({ subtype: "generic", damageChannels: ["infrastructure"], falseTrackBehavior: "none", routingProfile: "direct", ...values });

export const THREAT_RULES = Object.freeze({
  drone: threat({ class: "drone", signature: 0.86, classificationDifficulty: 18, interceptDifficulty: 20, routingProfile: "low-slow" }),
  saturation: threat({ class: "drone", signature: 0.94, classificationDifficulty: 24, interceptDifficulty: 32, subtype: "mass", routingProfile: "corridor-merge" }),
  geran2: threat({ class: "drone", signature: 0.82, classificationDifficulty: 24, interceptDifficulty: 26, subtype: "strike", damageChannels: ["infrastructure", "energy", "morale"], routingProfile: "low-slow" }),
  gerbera: threat({ class: "drone", signature: 0.68, classificationDifficulty: 34, interceptDifficulty: 18, subtype: "light-strike", damageChannels: ["morale"], routingProfile: "screen" }),
  decoy: threat({ class: "decoy", signature: 0.78, classificationDifficulty: 48, interceptDifficulty: 10, damageChannels: [], falseTrackBehavior: "non-damaging", routingProfile: "feint" }),
  parodiya: threat({ class: "decoy", signature: 0.72, classificationDifficulty: 54, interceptDifficulty: 12, subtype: "physical-decoy", damageChannels: [], falseTrackBehavior: "non-damaging", routingProfile: "feint" }),
  cruise: threat({ class: "cruise", signature: 0.72, classificationDifficulty: 38, interceptDifficulty: 40, routingProfile: "terrain-following" }),
  combined: threat({ class: "cruise", signature: 0.78, classificationDifficulty: 46, interceptDifficulty: 48, subtype: "mixed", damageChannels: ["infrastructure", "energy"], routingProfile: "split-screen" }),
  kh101: threat({ class: "cruise", signature: 0.62, classificationDifficulty: 52, interceptDifficulty: 46, subtype: "long-range", damageChannels: ["infrastructure", "energy"], routingProfile: "staggered" }),
  kalibr: threat({ class: "cruise", signature: 0.66, classificationDifficulty: 46, interceptDifficulty: 44, subtype: "sea-approach", damageChannels: ["infrastructure", "logistics"], routingProfile: "coastal-corridor" }),
  ballistic: threat({ class: "ballistic", signature: 1.12, classificationDifficulty: 28, interceptDifficulty: 64, damageChannels: ["infrastructure", "energy", "morale"], routingProfile: "direct" }),
  iskander: threat({ class: "ballistic", signature: 1.16, classificationDifficulty: 34, interceptDifficulty: 70, subtype: "aero-ballistic", damageChannels: ["infrastructure", "energy", "morale"], routingProfile: "direct" }),
  recon: { class: "support", subtype: "recon", signature: 0.58, classificationDifficulty: 58, interceptDifficulty: 30, damageChannels: ["wave-pressure"], falseTrackBehavior: "none", routingProfile: "probe" },
  "low-signature-cruise": { class: "cruise", subtype: "low-signature", signature: 0.48, classificationDifficulty: 70, interceptDifficulty: 58, damageChannels: ["infrastructure", "energy"], falseTrackBehavior: "none", routingProfile: "terrain-following" },
  jammer: { class: "support", subtype: "jammer", signature: 0.76, classificationDifficulty: 62, interceptDifficulty: 46, damageChannels: ["sensor-network"], falseTrackBehavior: "escort-clutter", routingProfile: "escort" },
});

export function unitRule(kind) { return UNIT_RULES[kind] || UNIT_RULES.mvg; }
export function threatRule(kind) { return THREAT_RULES[kind] || THREAT_RULES.drone; }
export function classificationTier(confidence) {
  if (confidence < 35) return "unknown";
  if (confidence < 60) return "probable-class";
  if (confidence < 85) return "confirmed-class";
  return "confirmed-type";
}

const typeLabels = { drone: "БПЛА", saturation: "група БПЛА", geran2: "Geran-2", gerbera: "Gerbera", decoy: "приманка", parodiya: "Parodiya", cruise: "крилата ціль", combined: "комбінована ціль", kh101: "X-101", kalibr: "Kalibr", ballistic: "балістична ціль", iskander: "балістична ціль", recon: "розвідувальна ціль", "low-signature-cruise": "малопомітна крилата ціль", jammer: "постановник перешкод" };
const classLabels = { drone: "БПЛА", decoy: "хибний контакт", cruise: "крилата ціль", ballistic: "балістична ціль", support: "ціль підтримки" };
export function threatDisplayLabel(kind, confidence) {
  const tier = classificationTier(confidence);
  if (tier === "unknown") return "Невідомий контакт";
  const classLabel = classLabels[threatRule(kind).class] || "повітряна ціль";
  if (tier === "probable-class") return `Ймовірно ${classLabel}`;
  if (tier === "confirmed-class") return `Підтверджено: ${classLabel}`;
  return `Тип підтверджено: ${typeLabels[kind] || classLabel}`;
}

export function supportLeakEffect(kind) {
  if (kind === "recon") return { wavePressure: 12, defensePenalty: 0.06, damaging: false };
  if (kind === "jammer") return { wavePressure: 6, defensePenalty: 0.04, damaging: false };
  return { wavePressure: 0, defensePenalty: 0, damaging: threatRule(kind).damageChannels.length > 0 };
}

export function salvoSizeFor(unitKind, threatKind, availableAmmo = 1) {
  const policy = unitRule(unitKind).doctrine.salvoPolicy;
  if (policy === "double") return Math.min(2, Math.max(1, availableAmmo));
  if (policy === "conditional-double" && threatRule(threatKind).class === "ballistic") return Math.min(2, Math.max(1, availableAmmo));
  return 1;
}

const clamp = (value, min = 0, max = 100) => Math.max(min, Math.min(max, value));
const statusFactor = (status) => status === "exhausted" ? 0.46 : status === "strained" ? 0.74 : status === "maintenance" ? 0 : 1;

export function acquisitionScore({ sensorKind, distanceKm, readiness = 85, status = "ready", threatKind, fusionSensorCount = 1, highAlert = false, intelFocus = false, wavePressure = 0, jammerPenalty = 0, primaryRangeKm, outerRangeKm, coastalBonus = 0 }) {
  const sensor = unitRule(sensorKind).sensor;
  if (!sensor) return 0;
  const ranges = Number.isFinite(primaryRangeKm) && Number.isFinite(outerRangeKm)
    ? [primaryRangeKm, outerRangeKm]
    : sensorKind === "small-radar" ? [50, 68] : sensorKind === "long-radar" ? [155, 185] : [95, 118];
  if (distanceKm > ranges[1]) return 0;
  const band = distanceKm <= ranges[0] ? 1 : 0.58;
  const target = threatRule(threatKind);
  const lowSignaturePenalty = target.signature < 0.7 ? sensor.lowSignaturePenalty : 0;
  const fusion = Math.max(0, fusionSensorCount - 1) * sensor.fusionValue;
  return clamp(sensor.acquisitionBase * band * (0.55 + readiness / 100 * 0.45) * statusFactor(status) * target.signature + fusion + coastalBonus + (highAlert ? 7 : 0) + (intelFocus ? 6 : 0) - lowSignaturePenalty - wavePressure * 0.05 - jammerPenalty, 0, 98);
}

export function classificationGain({ sensorKind, trackQuality = 0, fusionSensorCount = 1, threatKind, intelFocus = false, jammerPenalty = 0 }) {
  const sensor = unitRule(sensorKind).sensor;
  if (!sensor) return 0;
  const target = threatRule(threatKind);
  return clamp(sensor.classificationGain + Math.max(0, fusionSensorCount - 1) * sensor.fusionValue * 0.45 + trackQuality * 0.045 + (intelFocus ? 5 : 0) - target.classificationDifficulty * 0.09 - jammerPenalty, 1, 22);
}

export function fusedTrackQuality({ bestSensorScore = 0, sensorScores = [], continuity = 1, maneuver = 1 }) {
  const supporting = sensorScores.filter((score) => score > 0).slice(1).reduce((sum, score) => sum + score * 0.12, 0);
  return clamp((bestSensorScore + supporting) * continuity * maneuver, 0, 100);
}

export function fireControlScore({ trackQuality, confidence, networkRequired = true, networkAvailable = true, congestion = 0 }) {
  if (networkRequired && !networkAvailable) return 0;
  const confidenceFactor = confidence < 35 ? 0.62 : confidence < 60 ? 0.82 : confidence < 85 ? 0.94 : 1;
  return clamp(trackQuality * confidenceFactor - congestion * 4, 0, 100);
}

export function evaluateDoctrine({ unitKind, threatKind, confidence, trackQuality, reserveRatio = 1, lowerTierAvailable = false, manualOverride = false, networkAvailable = true, coastalApproach = true }) {
  const rules = unitRule(unitKind).doctrine;
  const override = manualOverride && rules.allowManualOverride;
  if (rules.coastalOnly && !coastalApproach) return { allowed: false, reason: "Катер працює лише у прибережному секторі" };
  if (rules.networkRequired && !networkAvailable) return { allowed: false, reason: "Немає мережевого супроводу" };
  if (!rules.allowedTargets.includes(threatKind) && !override) return { allowed: false, reason: unitKind === "patriot" ? "Резерв для балістичних цілей" : "Вогонь заборонено доктриною" };
  if (rules.forbiddenByDefault.includes(threatKind) && !override) return { allowed: false, reason: rules.reservedFor.length ? "Резерв для пріоритетних цілей" : "Вогонь заборонено доктриною" };
  if (confidence < rules.minConfidenceToEngage && !override) return { allowed: false, reason: "Недостатня класифікація" };
  if (trackQuality < rules.minTrackQuality && !override) return { allowed: false, reason: "Недостатня якість супроводу" };
  if (reserveRatio <= rules.conserveAmmoThreshold && rules.reservedFor.length && !rules.reservedFor.includes(threatKind) && !override) return { allowed: false, reason: "Економія БК: резерв збережено" };
  if (rules.cheapFirstPolicy && lowerTierAvailable && !rules.reservedFor.includes(threatKind) && !override) return { allowed: false, reason: "Ціль передана нижчому ешелону" };
  return { allowed: true, reason: override ? "Ручний дозвіл" : "Доктрина дозволяє" };
}

export function engagementProbability({ base, bandAccuracy, readiness, status = "ready", fatigue = 0, confidence, trackQuality, saturation = 1, conserveAmmo = false, experience = 0, threatKind, coastalBonus = 0 }) {
  const target = threatRule(threatKind);
  const confidenceFactor = confidence < 35 ? 0.62 : confidence < 60 ? 0.82 : confidence < 85 ? 0.94 : 1;
  const trackFactor = 0.55 + clamp(trackQuality) / 100 * 0.45;
  return clamp((base * 0.68 + bandAccuracy * 0.32) * (0.42 + readiness / 100 * 0.58) * statusFactor(status) * confidenceFactor * trackFactor - fatigue * 0.18 - Math.max(0, saturation - 1) * 8 - (conserveAmmo ? 7 : 0) - target.interceptDifficulty * 0.08 + experience * 1.5 + coastalBonus, 0, 98);
}

export function ewEffectFor({ threatKind, confidence, trackQuality, random = 0.5 }) {
  const targetClass = threatRule(threatKind).class;
  const score = clamp(24 + confidence * 0.34 + trackQuality * 0.28 - threatRule(threatKind).interceptDifficulty * 0.25 + random * 18, 0, 100);
  if (score < 42) return { success: false, effect: "disrupted", score };
  if (targetClass === "decoy") return { success: true, effect: "guidance-lost", score };
  if (threatKind === "gerbera") return { success: true, effect: random > 0.45 ? "diverted" : "guidance-lost", score };
  if (targetClass === "drone") return { success: true, effect: random > 0.62 ? "diverted" : "delayed", score };
  return { success: true, effect: score > 76 ? "guidance-lost" : "degraded", score };
}

export function planEffectivenessForThreat(plan = {}, threatKind) {
  const assets = Array.isArray(plan.assets) ? plan.assets : [];
  if (!assets.length) return null;
  const sensors = assets.filter((asset) => unitRule(asset?.kind).roleClass === "sensor");
  const networkAvailable = sensors.length > 0;
  const confidence = clamp(38 + sensors.reduce((sum, asset) => sum + (unitRule(asset.kind).sensor?.fusionValue || 0), 0), 20, 92);
  const trackQuality = clamp(42 + sensors.length * 10, 20, 94);
  const candidates = assets.filter((asset) => {
    const result = evaluateDoctrine({ unitKind: asset?.kind, threatKind, confidence, trackQuality, networkAvailable, reserveRatio: 1, coastalApproach: true });
    return result.allowed && unitRule(asset?.kind).roleClass !== "sensor";
  });
  if (!candidates.length) return { probability: 0.08, confidence, trackQuality, eligibleAssets: 0 };
  const readiness = candidates.reduce((sum, asset) => sum + clamp(Number(asset.readiness || 75)), 0) / candidates.length;
  const roleWeight = candidates.reduce((sum, asset) => sum + ({ gun: 0.08, shorad: 0.12, mrad: 0.16, "area-defense": 0.18, "upper-tier": 0.22, ew: 0.07, specialist: 0.1 }[unitRule(asset.kind).roleClass] || 0), 0);
  const salvoSize = Math.max(...candidates.map((asset) => salvoSizeFor(asset.kind, threatKind, 2)));
  return { probability: clamp(0.16 + sensors.length * 0.06 + roleWeight + readiness / 100 * 0.16, 0.08, 0.9), confidence, trackQuality, eligibleAssets: candidates.length, salvoSize };
}

export const TARGET_GROUPS = Object.freeze({ drones: DRONES, decoys: DECOYS, cruise: CRUISE, ballistic: BALLISTIC, support: SUPPORT, all: ALL_THREATS });
