import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { unitDefinitions } from "../src/data/units";
import { resolveLocale } from "../src/platform/i18n";

test("combat unit catalog exposes unique tactical codes and Ukrainian copy", () => {
  const codes = unitDefinitions.map((unit) => unit.technicalCode);
  assert.equal(new Set(codes).size, unitDefinitions.length);
  assert.ok(codes.every((code) => /^[A-Z0-9-]+$/.test(code)));
  assert.ok(unitDefinitions.every((unit) => /[А-Яа-яІіЇїЄє]/.test(unit.description)));
  assert.equal(resolveLocale(), "uk");
});

test("intel panel reuses the existing log and placement preview stays Leaflet-native and desktop-only", async () => {
  const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
  const map = await readFile(new URL("../src/components/TacticalMap.tsx", import.meta.url), "utf8");
  const legend = await readFile(new URL("../src/components/MapLegend.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../src/styles/app.css", import.meta.url), "utf8");
  const previewStart = map.indexOf("function DesktopPlacementPreview");
  const previewEnd = map.indexOf("function MapViewportTracker", previewStart);
  const preview = map.slice(previewStart, previewEnd);

  assert.equal((app.match(/<IntelLog game=\{game\} \/>/g) || []).length, 1);
  assert.match(legend, /Оперативна обстановка/);
  assert.match(legend, /game\.liveThreats/);
  assert.match(legend, /game\.engagementEvents/);
  assert.match(legend, /game\.impacts/);
  assert.match(preview, /\(hover: hover\) and \(pointer: fine\) and \(min-width: 821px\)/);
  assert.match(preview, /L\.layerGroup\(\)/);
  assert.match(preview, /map\.on\("mousemove", showAt\)/);
  assert.doesNotMatch(preview, /setInterval|setState/);
  assert.match(styles, /\.shell--mobile-live \.unit-hover-card \{ display: none !important; \}/);
  assert.match(styles, /\.placement-preview-ring--outer/);
  assert.match(styles, /\.intel-panel__metrics/);
});

test("combat results use tactical effects and desktop unit details keep readable layout", async () => {
  const map = await readFile(new URL("../src/components/TacticalMap.tsx", import.meta.url), "utf8");
  const rail = await readFile(new URL("../src/components/UnitRail.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../src/styles/app.css", import.meta.url), "utf8");

  assert.match(map, /combat-result-marker--\$\{marker\.tone\}/);
  assert.doesNotMatch(map, /markerSprites\.(impactEvent|interceptedThreat)/);
  assert.match(styles, /\.combat-result-marker__ring/);
  assert.match(styles, /@keyframes combat-result-ring/);
  assert.match(styles, /\.command-drawer \.unit-card > strong/);
  assert.match(styles, /--unit-details-height/);
  assert.match(rail, /details\?\.scrollHeight/);
  assert.doesNotMatch(styles, /min-height: 150px;[\s\S]*?max-height: 180px;/);
  assert.match(rail, /keepExpandedCardVisible/);
  assert.match(rail, /showStatus = tacticalStatus\.label !== "READY"/);
  assert.match(rail, /!isRadar \? <span><small>БК<\/small>/);
  assert.match(rail, /Радіус виявлення/);
  assert.match(map, /#63c7d4/);
  assert.match(map, /placement-preview-ring--radar/);
  assert.match(styles, /\.coverage-ring--radar[\s\S]*?99, 199, 212/);
});
