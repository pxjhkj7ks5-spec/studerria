import assert from "node:assert/strict";
import test from "node:test";
import { getUnitDefinition } from "../src/data/units";
import { acquisitionScore, classificationGain, evaluateDoctrine, ewEffectFor, planEffectivenessForThreat, salvoSizeFor, supportLeakEffect, THREAT_RULES, threatDisplayLabel } from "../src/game/airDefenseRules.mjs";
import { campaignMissionObjective, createCampaignState, serviceCampaignBattery } from "../src/game/campaignMeta";
import { createScenarioState } from "../src/game/initialState";
import { placeBattery, setBatteryManualOverride, tickSimulation } from "../src/game/liveSimulation";
import { validateBatteryPlacement } from "../src/game/placementRules";

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

test("campaign stock is the source for intermission mission-reserve replenishment", () => {
  let game = createScenarioState(() => .5, "crisis", "thirty-days-under-pressure");
  game.campaign = createCampaignState();
  game.campaign.missionGrantApplied = true;
  game.campaign.intermission = true;
  game.campaign.campaignWallet = 100;
  game.resources.budget = 100;
  game = placeBattery({ ...game, campaign: { ...game.campaign, intermission: false } }, "mvg", { lat: 49.1, lng: 29.7 }, () => .5);
  game.campaign!.intermission = true;
  const battery = game.batteries[0];
  battery.missionReserve = 0;
  game.campaign!.campaignAmmoStock = 3;
  game = serviceCampaignBattery(game, battery.id, "resupply", 1);
  assert.equal(game.batteries[0].missionReserve, 3);
  assert.equal(game.campaign!.campaignAmmoStock, 0);
  const wallet = game.campaign!.campaignWallet;
  game = serviceCampaignBattery(game, battery.id, "resupply", 1);
  assert.equal(game.campaign!.campaignWallet, wallet);
  assert.equal(game.placementWarning, "Стратегічний запас відсутній");
});

test("low confidence UI data hides exact type until confirmed-type threshold", () => {
  assert.equal(threatDisplayLabel("kh101", 20), "Невідомий контакт");
  assert.equal(threatDisplayLabel("kh101", 48), "Ймовірно крилата ціль");
  assert.equal(threatDisplayLabel("kh101", 72), "Підтверджено: крилата ціль");
  assert.equal(threatDisplayLabel("kh101", 90), "Тип підтверджено: X-101");
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
