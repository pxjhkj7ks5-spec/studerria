import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  formatThreatAltitude,
  formatThreatSpeed,
  threatDisplayName,
  threatFlightProfiles,
  threatTelemetryFor,
} from "../src/data/threatFlightProfiles";

test("every threat kind has deterministic realistic label telemetry", () => {
  for (const [kind, profile] of Object.entries(threatFlightProfiles)) {
    const first = threatTelemetryFor(kind as keyof typeof threatFlightProfiles, `${kind}-one`);
    const repeated = threatTelemetryFor(kind as keyof typeof threatFlightProfiles, `${kind}-one`);
    assert.deepEqual(first, repeated);
    assert.ok(first.speedKph >= profile.speedKph[0] && first.speedKph <= profile.speedKph[1]);
    assert.ok(first.altitudeM >= profile.altitudeM[0] && first.altitudeM <= profile.altitudeM[1]);
    assert.ok(threatDisplayName(kind as keyof typeof threatFlightProfiles).length > 0);
  }

  assert.notDeepEqual(threatTelemetryFor("geran2", "track-one"), threatTelemetryFor("geran2", "track-two"));
  assert.equal(formatThreatSpeed(183), "180 км/год");
  assert.equal(formatThreatAltitude(120), "120 м");
  assert.equal(formatThreatAltitude(10_500), "10.5 км");
});

test("target labels stay inside the imperative Leaflet marker and avoid per-frame DOM replacement", async () => {
  const source = await readFile(new URL("../src/components/TacticalMap.tsx", import.meta.url), "utf8");
  const styles = await readFile(new URL("../src/styles/app.css", import.meta.url), "utf8");
  const movingLayerStart = source.indexOf("function MovingObjectsLayer");
  const movingLayerEnd = source.indexOf("function usePerformanceStats", movingLayerStart);
  const movingLayer = source.slice(movingLayerStart, movingLayerEnd);

  assert.match(source, /class=\"target-label target-label--\$\{labelStatus\}\"/);
  assert.match(source, /<ThreatLabelZoomMode \/>/);
  assert.match(movingLayer, /L\.marker\(\[current\.lat, current\.lng\], \{ icon: makeThreatIcon\(threat\), interactive: false \}\)/);
  assert.match(movingLayer, /pooled\.iconKey !== iconKey/);
  assert.doesNotMatch(movingLayer, /setInterval/);
  for (const status of ["radar", "confirmed", "intercepted", "hit"]) {
    assert.match(styles, new RegExp(`\\.target-label--${status}\\s*\\{`));
  }
  assert.match(styles, /\.leaflet-stage\.threat-labels--far \.target-label__metrics/);
});
