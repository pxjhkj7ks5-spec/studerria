import assert from "node:assert/strict";
import { readdir, readFile, stat } from "node:fs/promises";
import test from "node:test";
import { normalizeAudioPreferences } from "../src/platform/audioPreferences";
import { collectUnseenSoundCues } from "../src/audio/useGameAudio";
import { cueAllowedAt, selectSoundVariant, soundCueDefinitions, soundCueNames } from "../src/audio/soundCues";
import { createScenarioState } from "../src/game/initialState";
import { placeBattery, tickSimulation } from "../src/game/liveSimulation";
import type { IntelEntry, LiveThreat } from "../src/types/game";

test("audio preferences normalize storage input and clamp volumes", () => {
  assert.deepEqual(normalizeAudioPreferences(null), { enabled: true, masterVolume: .65, combatVolume: .9, interfaceVolume: .55 });
  assert.deepEqual(normalizeAudioPreferences({ enabled: false, masterVolume: 2, combatVolume: -.5, interfaceVolume: .4 }), { enabled: false, masterVolume: 1, combatVolume: 0, interfaceVolume: .4 });
  assert.deepEqual(normalizeAudioPreferences({ enabled: "yes", masterVolume: "loud" }), { enabled: true, masterVolume: .65, combatVolume: .9, interfaceVolume: .55 });
});

test("every typed cue has bounded playback policy and variation avoids immediate repeats", () => {
  assert.deepEqual(Object.keys(soundCueDefinitions).sort(), [...soundCueNames].sort());
  for (const cue of soundCueNames) {
    const definition = soundCueDefinitions[cue];
    assert.ok(definition.cooldownMs >= 0);
    assert.ok(definition.maxVoices >= 1 && definition.maxVoices <= 3);
    assert.ok(definition.variants.length >= 1);
    assert.ok(definition.variants.every((variant) => variant.file.startsWith("audio/sfx/") && variant.file.endsWith(".mp3")));
  }
  assert.equal(selectSoundVariant("placement.success", 0, () => 0), 1);
  assert.equal(cueAllowedAt("alert.air-raid", undefined, 100), true);
  assert.equal(cueAllowedAt("alert.air-raid", 100, 11_000), false);
  assert.equal(cueAllowedAt("alert.air-raid", 100, 12_100), true);
});

test("hydrated entries form a baseline and only new semantic cues play in chronological order", () => {
  const existing: IntelEntry = { id: "existing", time: "20:00", title: "Old", body: "Old", tone: "info", soundCue: "result.impact" };
  const seen = new Set([existing.id]);
  assert.deepEqual(collectUnseenSoundCues([existing], seen), []);
  const latest: IntelEntry = { id: "latest", time: "20:02", title: "Latest", body: "Latest", tone: "success", soundCue: "result.intercept" };
  const earlier: IntelEntry = { id: "earlier", time: "20:01", title: "Earlier", body: "Earlier", tone: "warning", soundCue: "contact.detected" };
  assert.deepEqual(collectUnseenSoundCues([latest, earlier, existing], seen), ["contact.detected", "result.intercept"]);
});

test("shipped audio is fully registered, CC0 documented, and remains below the six megabyte budget", async () => {
  const audioRoot = new URL("../public/audio/", import.meta.url);
  const files = (await readdir(new URL("sfx/", audioRoot))).filter((file) => file.endsWith(".mp3"));
  const totalBytes = (await Promise.all(files.map((file) => stat(new URL(`sfx/${file}`, audioRoot))))).reduce((sum, file) => sum + file.size, 0);
  const attribution = await readFile(new URL("ATTRIBUTION.md", audioRoot), "utf8");
  assert.ok(totalBytes < 6 * 1024 * 1024);
  assert.ok(files.length >= 10);
  for (const file of files) {
    assert.ok(attribution.includes(`| \`${file}\` |`));
  }
  assert.equal((attribution.match(/CC0 1\.0/g) || []).length, files.length + 1);
});

test("live placement, detection, engagement, and impact logs carry semantic sound cues", () => {
  let game = createScenarioState(() => .5, "training", "first-night");
  game = placeBattery(game, "radar", { lat: 49.2, lng: 29.4 }, () => .5);
  assert.equal(game.log[0].soundCue, "placement.success");

  game = placeBattery(game, "mvg", { lat: 49.1, lng: 29.7 }, () => .5);
  const threat: LiveThreat = {
    id: "audio-threat",
    kind: "geran2",
    status: "inbound",
    origin: { lat: 49.2, lng: 29.4 },
    target: { lat: 49.2, lng: 30.4 },
    targetCityId: "kyiv",
    launchSectorId: "test-sector",
    launchSectorName: "Test sector",
    progress: 0,
    speed: 1 / 120_000,
    speedKph: 180,
    altitudeM: 120,
    difficulty: 10,
    damage: 3,
    confidence: 25,
    classification: "unknown",
    displayLabel: "Невідомий контакт",
    saturation: 1,
    headingDeg: 90,
    revealed: false,
    trackQuality: 0,
    fireControlQuality: 0,
    speedModifier: 1,
    damageModifier: 1,
    reward: 2,
  };
  game.cyclePhase = "attack";
  game.cycleDurationMs = 999_999;
  game.liveThreats = [threat];
  game.elapsedMs = 900;
  game = tickSimulation(game, 100, () => .01);
  assert.ok(game.log.some((entry) => entry.soundCue === "contact.detected"));

  game.liveThreats = [{ ...threat, id: "impact-audio-threat", revealed: true, confidence: 95, classification: "confirmed-type", displayLabel: "Geran-2", progress: .999, speed: .01 }];
  game = tickSimulation(game, 100, () => .5);
  assert.ok(game.log.some((entry) => entry.soundCue === "result.impact"));
});
