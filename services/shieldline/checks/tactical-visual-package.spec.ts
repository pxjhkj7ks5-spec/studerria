import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { normalizeDisplayPreferences, resolveReducedQuality } from "../src/platform/displayPreferences";
import { classifyThreatRoute, predictedRouteEndpoint } from "../src/game/threatRouteVisuals";

test("threat routes distinguish hidden, predicted and confirmed tracks", () => {
  assert.equal(classifyThreatRoute({ revealed: false, confidence: 100, status: "inbound" }, false), "hidden");
  assert.equal(classifyThreatRoute({ revealed: true, confidence: 34, status: "inbound" }, false), "hidden");
  assert.equal(classifyThreatRoute({ revealed: true, confidence: 35, status: "inbound" }, false), "predicted");
  assert.equal(classifyThreatRoute({ revealed: true, confidence: 57, status: "inbound" }, true), "hidden");
  assert.equal(classifyThreatRoute({ revealed: true, confidence: 58, status: "inbound" }, true), "confirmed");
  assert.equal(classifyThreatRoute({ revealed: true, confidence: 20, status: "engaged" }, true), "confirmed");
  const endpoint = predictedRouteEndpoint({ lat: 0, lng: 0 }, { lat: 10, lng: 20 });
  assert.ok(Math.abs(endpoint.lat - 3.4) < 1e-9);
  assert.ok(Math.abs(endpoint.lng - 6.8) < 1e-9);
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
