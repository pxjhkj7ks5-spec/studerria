import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { normalizeDisplayPreferences, resolveReducedQuality } from "../src/platform/displayPreferences";
import { advanceVisualThreatProgress, classifyThreatRoute, predictedRouteEndpoint, threatCourseAtProgress, threatPositionAtProgress, threatRouteAtProgress } from "../src/game/threatRouteVisuals";
import type { LiveThreat } from "../src/types/game";

test("threat routes distinguish hidden, predicted and confirmed tracks", () => {
  assert.equal(classifyThreatRoute({ revealed: false, confidence: 100, status: "inbound" }, false), "hidden");
  assert.equal(classifyThreatRoute({ revealed: true, confidence: 34, status: "inbound" }, false), "hidden");
  assert.equal(classifyThreatRoute({ revealed: true, confidence: 35, status: "inbound" }, false), "predicted");
  assert.equal(classifyThreatRoute({ revealed: true, confidence: 57, status: "inbound" }, true), "hidden");
  assert.equal(classifyThreatRoute({ revealed: true, confidence: 60, status: "inbound" }, true), "confirmed");
  assert.equal(classifyThreatRoute({ revealed: true, confidence: 20, status: "engaged" }, true), "confirmed");
  const endpoint = predictedRouteEndpoint({ lat: 0, lng: 0 }, { lat: 10, lng: 20 });
  assert.ok(Math.abs(endpoint.lat - 3.4) < 1e-9);
  assert.ok(Math.abs(endpoint.lng - 6.8) < 1e-9);
  assert.ok(Math.abs(advanceVisualThreatProgress(0.52, 0.49, 0.0001, 16) - 0.5216) < 1e-9);
  assert.equal(advanceVisualThreatProgress(0.4, 0.56, 0.0001, 16), 0.56);
  assert.ok(Math.abs(advanceVisualThreatProgress(0.4, 0.41, 0.0001, 1_000) - 0.41) < 1e-9);
  const eased = advanceVisualThreatProgress(0.4, 0.405, 0.0001, 16);
  assert.ok(eased > 0.4016 && eased < 0.405);
});

test("route sampling follows distance, turns the sprite locally and keeps predicted geometry stable", async () => {
  const threat = {
    origin: { lat: 0, lng: 0 },
    target: { lat: 2, lng: 2 },
    routeWaypoints: [{ lat: 0, lng: 0 }, { lat: 0, lng: 2 }, { lat: 2, lng: 2 }],
  } as LiveThreat;
  const first = threatPositionAtProgress(threat, .25);
  const second = threatPositionAtProgress(threat, .75);
  assert.ok(Math.abs(first.lat) < .001 && first.lng > .9 && first.lng < 1.1);
  assert.ok(second.lat > .9 && second.lat < 1.1 && Math.abs(second.lng - 2) < .001);
  assert.ok(threatCourseAtProgress(threat, .25) > 85 && threatCourseAtProgress(threat, .25) < 95);
  assert.ok(threatCourseAtProgress(threat, .75) < 5 || threatCourseAtProgress(threat, .75) > 355);

  const predicted = threatRouteAtProgress(threat, .1, "predicted");
  const confirmed = threatRouteAtProgress(threat, .1, "confirmed");
  assert.deepEqual(predicted, confirmed.slice(0, predicted.length));

  const mapSource = await readFile(new URL("../src/components/TacticalMap.tsx", import.meta.url), "utf8");
  assert.match(mapSource, /route: L\.Polyline/);
  assert.match(mapSource, /updateThreatMarkerCourse/);
  assert.doesNotMatch(mapSource, /previousRouteVisual|pooled\.route = null/);
});

test("unidentified contacts use red tactical symbols instead of generic target artwork", async () => {
  const mapSource = await readFile(new URL("../src/components/TacticalMap.tsx", import.meta.url), "utf8");
  const spriteCatalog = await readFile(new URL("../src/assets/sprites/spriteCatalog.ts", import.meta.url), "utf8");
  const styles = await readFile(new URL("../src/styles/app.css", import.meta.url), "utf8");

  assert.match(mapSource, /threat\.confidence >= 85/);
  assert.match(mapSource, /target-contact--\$\{threat\.confidence < 35 \? "unknown" : "classified"\}/);
  assert.match(mapSource, /threat\.confidence < 35 \? "\?" : "•"/);
  assert.doesNotMatch(mapSource, /classSprite|unknownThreatSprite/);
  assert.doesNotMatch(spriteCatalog, /unknownThreatSprite/);
  assert.match(styles, /\.target-contact[\s\S]*?color: #ff625a/);
});

test("engagement visuals stay bound to the marker for their target id", async () => {
  const mapSource = await readFile(new URL("../src/components/TacticalMap.tsx", import.meta.url), "utf8");

  assert.match(mapSource, /threatPool\.get\(event\.targetId\)\?\.marker\.getLatLng\(\)/);
  assert.match(mapSource, /boundEngagementTargetPosition\(event, threatPoolRef\.current, pooled\.targetPosition\)/);
  assert.match(mapSource, /updateEngagementVisual\(map, event, pooled,[\s\S]*?targetPosition\)/);
  assert.doesNotMatch(mapSource, /coordinateBetween\(event\.startPosition, event\.targetPredictedPosition/);
});

test("display preferences are visual-only, normalized and performance mode overrides automatic quality", async () => {
  assert.deepEqual(normalizeDisplayPreferences(null), { environmentTime: "night", environmentWeather: "clear", performanceMode: false });
  assert.deepEqual(normalizeDisplayPreferences({ environmentTime: "day", environmentWeather: "fog", performanceMode: true }), { environmentTime: "day", environmentWeather: "fog", performanceMode: true });
  assert.deepEqual(normalizeDisplayPreferences({ environmentTime: "sunset", environmentWeather: "storm" }), { environmentTime: "night", environmentWeather: "clear", performanceMode: false });
  assert.equal(resolveReducedQuality(false, false), false);
  assert.equal(resolveReducedQuality(true, false), true);
  assert.equal(resolveReducedQuality(false, true), true);

  const settingsSource = await readFile(new URL("../src/components/DisplaySettings.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(settingsSource, /useGameStore|forecast|setGame/);
});

test("completion opens the accessible full-screen report with both exits", async () => {
  const appSource = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
  const reportSource = await readFile(new URL("../src/components/AfterActionReport.tsx", import.meta.url), "utf8");
  assert.match(appSource, /setFullscreenReportOpen\(true\)/);
  assert.match(appSource, /role="dialog" aria-modal="true"/);
  assert.match(reportSource, /Оглянути мапу/);
  assert.match(reportSource, /До вибору режимів/);
  assert.match(reportSource, /event\.key !== "Escape"/);
});
