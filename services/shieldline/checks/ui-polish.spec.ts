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
