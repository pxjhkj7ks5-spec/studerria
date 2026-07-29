import assert from "node:assert/strict";
import test from "node:test";
import { getUnitDefinition } from "../src/data/units";
import { acquisitionScore, classificationGain, evaluateDoctrine, ewEffectFor, planEffectivenessForThreat, salvoSizeFor, supportLeakEffect, THREAT_RULES, threatDisplayLabel, UNIT_RULES } from "../src/game/airDefenseRules.mjs";
import { campaignMissionObjective, createCampaignState } from "../src/game/campaignMeta";
import { createScenarioState } from "../src/game/initialState";
import { placeBattery, setBatteryManualOverride, tickSimulation } from "../src/game/liveSimulation";
import { validateBatteryPlacement } from "../src/game/placementRules";
import type { LiveThreat } from "../src/types/game";

const doctrineInput = { confidence: 90, trackQuality: 90, networkAvailable: true, reserveRatio: 1, coastalApproach: true };

test("upper-tier doctrine reserves Patriot and only explicit manual override opens cheap targets", () => {
  const patriotDrone = evaluateDoctrine({ ...doctrineInput, unitKind: "patriot", threatKind: "geran2" });
  assert.equal(patriotDrone.allowed, false);
  assert.equal(patriotDrone.reason, "Резерв для балістичних цілей");
  assert.equal(evaluateDoctrine({ ...doctrineInput, unitKind: "patriot", threatKind: "decoy" }).allowed, false);
  assert.equal(evaluateDoctrine({ ...doctrineInput, unitKind: "patriot", threatKind: "geran2", manualOverride: true }).allowed, true);
  assert.equal(evaluateDoctrine({ ...doctrineInput, unitKind: "ew", threatKind: "iskander", manualOverride: true }).allowed, false);

  let game = createScenarioState(() => .5, "training", "first-night");
  game.resources.budget = 999;
  game = placeBattery(game, "patriot", { lat: 49.1, lng: 29.7 }, () => .5);
  const battery = game.batteries[0];
  game = setBatteryManualOverride(game, battery.id, "geran2", true);
  assert.deepEqual(game.batteries[0].manualOverrideTargets, ["geran2"]);
});

test("manual drone permission leaves every upper-tier system with a real firing chance", () => {
  for (const unitKind of ["s300", "iris-t", "nasams", "patriot"] as const) {
    const unit = getUnitDefinition(unitKind);
    for (const threatKind of ["drone", "saturation", "geran2", "gerbera", "recon"] as const) {
      if (!unit.doctrine.forbiddenByDefault.includes(threatKind)) continue;
      assert.ok(unit.engagementChanceByThreat[threatKind] > 0, `${unitKind} must have a firing chance against ${threatKind}`);
      assert.equal(evaluateDoctrine({ ...doctrineInput, unitKind, threatKind, manualOverride: true }).allowed, true);
    }
  }
  assert.equal(getUnitDefinition("s300").engagementChanceByThreat.geran2, 42);
  assert.equal(getUnitDefinition("s300").engagementChanceByThreat.gerbera, 43);
});

test("an S-300 with manual permission actually launches at a drone", () => {
  let game = createScenarioState(() => .5, "training", "first-night");
  game.resources.budget = 999;
  game = placeBattery(game, "s300", { lat: 49.1, lng: 29.7 }, () => .5);
  const battery = game.batteries[0];
  game = setBatteryManualOverride(game, battery.id, "gerbera", true);
  game.cyclePhase = "attack";
  game.cycleDurationMs = 999_999;
  const drone: LiveThreat = {
    id: "manual-s300-drone",
    kind: "gerbera",
    status: "inbound",
    origin: { lat: 49.1, lng: 29.7 },
    target: { lat: 49.2, lng: 29.8 },
    targetCityId: "kyiv",
    launchSectorId: "manual-test",
    launchSectorName: "Тестовий напрямок",
    progress: .3,
    speed: 1 / 120_000,
    speedKph: 150,
    altitudeM: 140,
    difficulty: 10,
    damage: 4,
    confidence: 90,
    classification: "confirmed-type",
    displayLabel: "Gerbera",
    saturation: 1,
    headingDeg: 0,
    revealed: true,
    trackQuality: 90,
    fireControlQuality: 90,
    speedModifier: 1,
    damageModifier: 1,
    reward: 2,
  };
  game.liveThreats = [drone];
  game = tickSimulation(game, 100, () => .5);
  assert.ok(game.engagementEvents.some((event) => event.unitId === battery.id && event.targetId === drone.id));
  assert.equal(game.batteries[0].currentAmmo, 3);
});

test("network SAM doctrine yields drone work to an available cheaper layer", () => {
  for (const unitKind of ["nasams", "iris-t"] as const) {
    const decision = evaluateDoctrine({ ...doctrineInput, unitKind, threatKind: "geran2", lowerTierAvailable: true });
    assert.equal(decision.allowed, false);
    assert.equal(decision.reason, "Ціль передана нижчому ешелону");
    assert.equal(evaluateDoctrine({ ...doctrineInput, unitKind, threatKind: "gerbera" }).allowed, false);
  }
});

test("EW resolves to a soft-kill effect rather than a hard interception result", () => {
  const result = ewEffectFor({ threatKind: "gerbera", confidence: 92, trackQuality: 88, random: .8 });
  assert.equal(result.success, true);
  assert.ok(["diverted", "guidance-lost", "delayed", "degraded", "disrupted"].includes(result.effect));
  assert.notEqual(result.effect, "intercepted");
});

test("combat reload transfers a magazine from mission reserve and stops when reserve is empty", () => {
  let game = createScenarioState(() => .5, "training", "first-night");
  game = placeBattery(game, "mvg", { lat: 49.1, lng: 29.7 }, () => .5);
  let battery = game.batteries[0];
  battery.currentAmmo = 0;
  battery.missionReserve = 3;
  battery.status = "reloading";
  battery.reloadRemainingMs = 100;
  game = tickSimulation(game, 100, () => .99);
  battery = game.batteries[0];
  assert.equal(battery.currentAmmo, 3);
  assert.equal(battery.missionReserve, 0);

  battery.currentAmmo = 0;
  battery.missionReserve = 0;
  battery.status = "reloading";
  battery.reloadRemainingMs = 100;
  game = tickSimulation(game, 100, () => .99);
  assert.equal(game.batteries[0].currentAmmo, 0);
  assert.equal(game.batteries[0].status, "strained");
});

test("campaign batteries wait for a complete magazine and then draw it automatically from the depot", () => {
  let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game.campaign.missionGrantApplied = true;
  game = placeBattery(game, "mvg", { lat: 49.1, lng: 29.7 }, () => .5);
  const battery = game.batteries[0];
  battery.currentAmmo = 0;
  battery.status = "reloading";
  battery.reloadRemainingMs = 100;
  game.campaign!.depot.stock = 3;
  game = tickSimulation(game, 100, () => .99);
  assert.equal(game.batteries[0].currentAmmo, 0);
  assert.equal(game.batteries[0].status, "reloading");
  assert.equal(game.campaign!.depot.stock, 3);
  game.campaign!.depot.stock = 5;
  game = tickSimulation(game, 1, () => .99);
  assert.equal(game.batteries[0].currentAmmo, 5);
  assert.equal(game.campaign!.depot.stock, 0);
});

test("low confidence UI data hides exact type until confirmed-type threshold", () => {
  assert.equal(threatDisplayLabel("kh101", 20), "Невідомий контакт");
  assert.equal(threatDisplayLabel("kh101", 48), "Ймовірно крилата ціль");
  assert.equal(threatDisplayLabel("kh101", 72), "Підтверджено: крилата ціль");
  assert.equal(threatDisplayLabel("kh101", 90), "Тип підтверджено: X-101");
  assert.equal(threatDisplayLabel("recon", 48), "Ймовірно спеціальна ціль");
  assert.equal(threatDisplayLabel("recon", 90), "Тип підтверджено: розвідувальна ціль");
});

test("mission one objective has executable impact and resilience thresholds", () => {
  const game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game.impacts = 3;
  assert.equal(campaignMissionObjective(game, 1).objectiveMet, true);
  game.impacts = 4;
  assert.equal(campaignMissionObjective(game, 1).objectiveMet, false);
});

test("boat remains coastal-only and the radar line creates fusion without instant identification", () => {
  assert.equal(validateBatteryPlacement("boat", { lat: 49.1, lng: 29.7 }).allowed, false);
  const localBoat = acquisitionScore({ sensorKind: "boat", distanceKm: 14, readiness: 86, threatKind: "kalibr", primaryRangeKm: 24, outerRangeKm: 34 });
  const coastalBoat = acquisitionScore({ sensorKind: "boat", distanceKm: 14, readiness: 86, threatKind: "kalibr", primaryRangeKm: 24, outerRangeKm: 34, coastalBonus: 12 });
  assert.ok(localBoat > 0);
  assert.ok(coastalBoat > localBoat);
  const single = acquisitionScore({ sensorKind: "long-radar", distanceKm: 120, readiness: 84, status: "ready", threatKind: "kh101", fusionSensorCount: 1 });
  const fused = acquisitionScore({ sensorKind: "long-radar", distanceKm: 120, readiness: 84, status: "ready", threatKind: "kh101", fusionSensorCount: 2 });
  assert.ok(fused > single);
  assert.ok(classificationGain({ sensorKind: "long-radar", trackQuality: 70, fusionSensorCount: 1, threatKind: "kh101" }) < classificationGain({ sensorKind: "small-radar", trackQuality: 70, fusionSensorCount: 1, threatKind: "kh101" }));
});

test("browser and server resolution consume the same doctrine-aware rules contract", () => {
  const patriotOnly = planEffectivenessForThreat({ assets: [{ kind: "radar", readiness: 90 }, { kind: "patriot", readiness: 90 }] }, "geran2")!;
  const layered = planEffectivenessForThreat({ assets: [{ kind: "radar", readiness: 90 }, { kind: "gepard", readiness: 90 }] }, "geran2")!;
  assert.equal(patriotOnly.eligibleAssets, 0);
  assert.ok(layered.eligibleAssets > 0);
  assert.ok(layered.probability > patriotOnly.probability);
  assert.equal(getUnitDefinition("long-radar").sensorProfile?.fusionValue, 13);
});

test("support and low-signature target classes have executable sensor-network effects", () => {
  for (const kind of ["recon", "low-signature-cruise", "jammer"] as const) {
    const profile = THREAT_RULES[kind];
    assert.ok(profile.subtype);
    assert.ok(profile.routingProfile);
    assert.ok(Array.isArray(profile.damageChannels));
  }
  const clearAcquisition = acquisitionScore({ sensorKind: "radar", distanceKm: 70, readiness: 90, threatKind: "kh101" });
  const jammedAcquisition = acquisitionScore({ sensorKind: "radar", distanceKm: 70, readiness: 90, threatKind: "kh101", jammerPenalty: 14 });
  const clearClassification = classificationGain({ sensorKind: "radar", trackQuality: 70, threatKind: "kh101" });
  const jammedClassification = classificationGain({ sensorKind: "radar", trackQuality: 70, threatKind: "kh101", jammerPenalty: 5 });
  assert.ok(jammedAcquisition < clearAcquisition);
  assert.ok(jammedClassification < clearClassification);
  assert.equal(supportLeakEffect("recon").damaging, false);
  assert.ok(supportLeakEffect("recon").defensePenalty > supportLeakEffect("jammer").defensePenalty);
  assert.ok(THREAT_RULES["low-signature-cruise"].signature < THREAT_RULES.kh101.signature);
  assert.equal(salvoSizeFor("patriot", "iskander", 4), 2);
  assert.equal(salvoSizeFor("patriot", "kh101", 4), 1);
});

test("upper-tier batteries classify locally without becoming radar-network nodes", () => {
  const expected = {
    s300: [96, 20, 3, 8, 44, 32],
    "iris-t": [98, 22, 4, 6, 42, 34],
    nasams: [100, 22, 6, 6, 42, 34],
    patriot: [104, 24, 6, 4, 44, 36],
  } as const;
  for (const [kind, [acquisitionBase, gain, fusion, lowSignaturePenalty, confidence, track]] of Object.entries(expected)) {
    const rules = UNIT_RULES[kind];
    assert.deepEqual(
      [rules.sensor.acquisitionBase, rules.sensor.classificationGain, rules.sensor.fusionValue, rules.sensor.lowSignaturePenalty, rules.doctrine.minConfidenceToEngage, rules.doctrine.minTrackQuality],
      [acquisitionBase, gain, fusion, lowSignaturePenalty, confidence, track],
    );
    assert.equal(rules.doctrine.networkRequired, false);
    assert.notEqual(rules.roleClass, "sensor");
    const clearGain = classificationGain({ sensorKind: kind, trackQuality: 70, threatKind: "kh101" });
    const jammedGain = classificationGain({ sensorKind: kind, trackQuality: 70, threatKind: "kh101", jammerPenalty: 2.5 });
    assert.ok(22 + clearGain * 3 >= 85);
    assert.ok(22 + jammedGain * 5 >= 85);
  }
});
