import { ArrowLeft, RotateCcw, Save } from "lucide-react";
import { useMemo, useState } from "react";
import { defaultControlOverlay, getControlOverlay, resetControlOverlay, saveControlOverlay } from "../data/controlZones";
import type { ControlOverlay } from "../data/controlZones";
import type { Coordinates } from "../types/game";

function pretty(value: unknown) {
  return JSON.stringify(value, null, 2);
}

function parseCoordinates(value: string, field: string, minPoints: number): Coordinates[] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed)) throw new Error(`${field}: expected an array of { lat, lng } points.`);
  const points = parsed.map((point, index) => {
    const candidate = point as Coordinates;
    if (!Number.isFinite(candidate?.lat) || !Number.isFinite(candidate?.lng)) {
      throw new Error(`${field}: point ${index + 1} must contain numeric lat and lng.`);
    }
    return { lat: candidate.lat, lng: candidate.lng };
  });
  if (points.length < minPoints) throw new Error(`${field}: add at least ${minPoints} points.`);
  return points;
}

function parsePolygons(value: string, field: string): Coordinates[][] {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed)) throw new Error(`${field}: expected an array of polygons.`);
  return parsed.map((polygon, index) => parseCoordinates(pretty(polygon), `${field} polygon ${index + 1}`, 3));
}

export function ControlZoneAdmin() {
  const initialOverlay = useMemo(() => getControlOverlay(), []);
  const [frontline, setFrontline] = useState(pretty(initialOverlay.frontline));
  const [occupiedPolygons, setOccupiedPolygons] = useState(pretty(initialOverlay.occupiedPolygons));
  const [waterPolygons, setWaterPolygons] = useState(pretty(initialOverlay.waterPlacementPolygons));
  const [status, setStatus] = useState("Edit zones, then save. The live map uses saved values on the next render.");
  const basePath = import.meta.env.BASE_URL || "/shieldline/";

  const save = () => {
    try {
      const overlay: ControlOverlay = {
        ukrainePlacementPolygon: defaultControlOverlay.ukrainePlacementPolygon,
        occupiedPolygons: parsePolygons(occupiedPolygons, "Occupied zones"),
        frontline: parseCoordinates(frontline, "Front line", 2),
        waterPlacementPolygons: parsePolygons(waterPolygons, "Water placement zones"),
      };
      saveControlOverlay(overlay);
      setStatus("Saved. Return to the map to use the updated placement rules.");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Could not save zones.");
    }
  };

  const reset = () => {
    resetControlOverlay();
    setFrontline(pretty(defaultControlOverlay.frontline));
    setOccupiedPolygons(pretty(defaultControlOverlay.occupiedPolygons));
    setWaterPolygons(pretty(defaultControlOverlay.waterPlacementPolygons));
    setStatus("Reset to default editorial zones.");
  };

  return (
    <main className="admin-shell" aria-label="Shieldline control zone admin">
      <header className="admin-topbar">
        <a className="admin-back-link" href={basePath}>
          <ArrowLeft size={18} />
          Map
        </a>
        <div>
          <h1>Shieldline Zones</h1>
          <span>Configure occupied areas, front line, and water-only boat placement.</span>
        </div>
      </header>

      <section className="admin-status" aria-live="polite">
        {status}
      </section>

      <section className="admin-grid">
        <label className="admin-editor">
          <span>
            <strong>Occupied territory polygons</strong>
            <small>Array of polygons. Land PPO cannot be placed inside these zones.</small>
          </span>
          <textarea value={occupiedPolygons} onChange={(event) => setOccupiedPolygons(event.target.value)} spellCheck={false} />
        </label>

        <label className="admin-editor">
          <span>
            <strong>Front line</strong>
            <small>Array of points. A 10 km no-placement buffer is generated around this line.</small>
          </span>
          <textarea value={frontline} onChange={(event) => setFrontline(event.target.value)} spellCheck={false} />
        </label>

        <label className="admin-editor admin-editor--wide">
          <span>
            <strong>Water placement polygons</strong>
            <small>Boats can be placed only inside these water polygons, regardless of Ukraine or occupation zones.</small>
          </span>
          <textarea value={waterPolygons} onChange={(event) => setWaterPolygons(event.target.value)} spellCheck={false} />
        </label>
      </section>

      <footer className="admin-actions">
        <button type="button" onClick={reset}>
          <RotateCcw size={16} />
          Reset defaults
        </button>
        <button type="button" onClick={save}>
          <Save size={16} />
          Save zones
        </button>
      </footer>
    </main>
  );
}
