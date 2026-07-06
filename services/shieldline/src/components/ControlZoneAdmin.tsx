import { ArrowLeft, Lock, MousePointer2, RotateCcw, Save, Trash2, Undo2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { CircleMarker, MapContainer, Polygon, Polyline, TileLayer, useMapEvents } from "react-leaflet";
import {
  createOccupiedPolygonToPlacementEdge,
  defaultControlOverlay,
  getControlOverlay,
  resetControlOverlay,
  saveControlOverlay,
  saveControlOverlayToServer,
  verifyControlOverlayAdminPassword,
} from "../data/controlZones";
import type { ControlOverlay } from "../data/controlZones";
import { createLineBufferPolygons } from "../game/placementRules";
import type { Coordinates } from "../types/game";

type ZoneMode = "frontline" | "occupied" | "water";

const mapCenter: [number, number] = [48.7, 31.4];

const modeLabels: Record<ZoneMode, { title: string; help: string }> = {
  frontline: {
    title: "Front line",
    help: "Click the map to append front-line points. The no-placement buffer is generated automatically.",
  },
  occupied: {
    title: "Occupied zones",
    help: "Click at least three points around a blocked land area, then close the polygon.",
  },
  water: {
    title: "Water zones",
    help: "Click at least three points around water where boats may be placed, then close the polygon.",
  },
};

function toPositions(points: Coordinates[]): [number, number][] {
  return points.map((point) => [point.lat, point.lng]);
}

function pointFromEvent(event: { latlng: { lat: number; lng: number } }): Coordinates {
  return { lat: event.latlng.lat, lng: event.latlng.lng };
}

function ClickCapture({ onClick }: { onClick: (point: Coordinates) => void }) {
  useMapEvents({
    click(event) {
      onClick(pointFromEvent(event));
    },
  });
  return null;
}

function pointKey(point: Coordinates, index: number) {
  return `${index}-${point.lat.toFixed(4)}-${point.lng.toFixed(4)}`;
}

interface AdminMapProps {
  mode: ZoneMode;
  overlay: ControlOverlay;
  draftPolygon: Coordinates[];
  onMapClick: (point: Coordinates) => void;
}

function AdminZoneMap({ mode, overlay, draftPolygon, onMapClick }: AdminMapProps) {
  const frontBufferPolygons = useMemo(() => createLineBufferPolygons(overlay.frontline), [overlay.frontline]);
  const draftColor = mode === "water" ? "#5ad8ff" : mode === "occupied" ? "#ff6e6e" : "#ffcf6e";

  return (
    <MapContainer
      center={mapCenter}
      zoom={6}
      minZoom={5}
      maxZoom={12}
      zoomControl
      attributionControl={false}
      className="admin-map"
      scrollWheelZoom
    >
      <ClickCapture onClick={onMapClick} />
      <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" attribution="&copy; OpenStreetMap contributors" />
      <Polygon
        positions={toPositions(overlay.ukrainePlacementPolygon)}
        pathOptions={{ color: "#5edc8b", fillColor: "#5edc8b", fillOpacity: 0.025, opacity: 0.18, weight: 1 }}
      />
      {overlay.waterPlacementPolygons.map((polygon, index) => (
        <Polygon
          key={`water-${index}`}
          positions={toPositions(polygon)}
          pathOptions={{ color: "#5ad8ff", fillColor: "#2aa8ff", fillOpacity: 0.085, opacity: 0.36, weight: 1.2, dashArray: "4 7" }}
        />
      ))}
      {overlay.occupiedPolygons.map((polygon, index) => (
        <Polygon
          key={`occupied-${index}`}
          positions={toPositions(polygon)}
          pathOptions={{ color: "#ff4f4f", fillColor: "#ff4f4f", fillOpacity: 0.16, opacity: 0.56, weight: 1.4, dashArray: "6 5" }}
        />
      ))}
      {frontBufferPolygons.map((polygon, index) => (
        <Polygon
          key={`front-buffer-${index}`}
          positions={toPositions(polygon)}
          pathOptions={{ color: "#ff9f42", fillColor: "#ff8a35", fillOpacity: 0.16, opacity: 0.46, weight: 0.8, className: "frontline-buffer-zone" }}
        />
      ))}
      <Polyline positions={toPositions(overlay.frontline)} pathOptions={{ color: "#ff5c5c", weight: 3, opacity: 0.84, dashArray: "8 5" }} />
      {overlay.frontline.map((point, index) => (
        <CircleMarker
          key={`front-point-${pointKey(point, index)}`}
          center={[point.lat, point.lng]}
          radius={4}
          pathOptions={{ color: "#ffefb0", fillColor: "#ff5c5c", fillOpacity: 0.95, weight: 1.5 }}
        />
      ))}
      {draftPolygon.length ? (
        <>
          <Polyline positions={toPositions(draftPolygon)} pathOptions={{ color: draftColor, weight: 2.5, opacity: 0.92, dashArray: "3 5" }} />
          {draftPolygon.map((point, index) => (
            <CircleMarker
              key={`draft-${pointKey(point, index)}`}
              center={[point.lat, point.lng]}
              radius={5}
              pathOptions={{ color: "#fff4c7", fillColor: draftColor, fillOpacity: 0.94, weight: 1.6 }}
            />
          ))}
        </>
      ) : null}
    </MapContainer>
  );
}

export function ControlZoneAdmin() {
  const initialOverlay = useMemo(() => getControlOverlay(), []);
  const [overlay, setOverlay] = useState<ControlOverlay>(initialOverlay);
  const [mode, setMode] = useState<ZoneMode>("frontline");
  const [draftPolygon, setDraftPolygon] = useState<Coordinates[]>([]);
  const [password, setPassword] = useState(() => (typeof window === "undefined" ? "" : window.sessionStorage.getItem("shieldline-admin-password") || ""));
  const [authenticated, setAuthenticated] = useState(false);
  const [authChecking, setAuthChecking] = useState(false);
  const [status, setStatus] = useState("Enter the admin password to open zone editing.");
  const basePath = import.meta.env.BASE_URL || "/shieldline/";

  useEffect(() => {
    if (typeof window === "undefined") return;
    const storedPassword = window.sessionStorage.getItem("shieldline-admin-password") || "";
    if (!storedPassword) return;
    setAuthChecking(true);
    verifyControlOverlayAdminPassword(basePath, storedPassword)
      .then(() => {
        setPassword(storedPassword);
        setAuthenticated(true);
        setStatus("Click the map to update zones.");
      })
      .catch(() => {
        setAuthenticated(false);
        setStatus("Enter the admin password to open zone editing.");
      })
      .finally(() => setAuthChecking(false));
  }, [basePath]);

  const login = async () => {
    if (!password.trim()) {
      setStatus("Enter the Shieldline admin password.");
      return;
    }
    setAuthChecking(true);
    try {
      await verifyControlOverlayAdminPassword(basePath, password);
      if (typeof window !== "undefined") {
        window.sessionStorage.setItem("shieldline-admin-password", password);
      }
      setAuthenticated(true);
      setStatus("Click the map to update zones.");
    } catch (error) {
      setAuthenticated(false);
      setStatus(error instanceof Error ? error.message : "Invalid admin password.");
    } finally {
      setAuthChecking(false);
    }
  };

  const appendPoint = (point: Coordinates) => {
    if (mode === "frontline") {
      setOverlay((current) => ({ ...current, frontline: [...current.frontline, point] }));
      setStatus("Front-line point added.");
      return;
    }
    setDraftPolygon((current) => [...current, point]);
    setStatus(`${modeLabels[mode].title}: draft point added.`);
  };

  const undoPoint = () => {
    if (mode === "frontline") {
      setOverlay((current) => ({ ...current, frontline: current.frontline.slice(0, -1) }));
      setStatus("Last front-line point removed.");
      return;
    }
    setDraftPolygon((current) => current.slice(0, -1));
    setStatus("Last draft point removed.");
  };

  const closePolygon = () => {
    if (mode === "frontline") return;
    if (draftPolygon.length < 3) {
      setStatus("Add at least three map points before closing a polygon.");
      return;
    }
    setOverlay((current) => ({
      ...current,
      occupiedPolygons: mode === "occupied" ? [...current.occupiedPolygons, draftPolygon] : current.occupiedPolygons,
      waterPlacementPolygons: mode === "water" ? [...current.waterPlacementPolygons, draftPolygon] : current.waterPlacementPolygons,
    }));
    setDraftPolygon([]);
    setStatus(`${modeLabels[mode].title}: polygon closed.`);
  };

  const fillOccupiedToPlacementEdge = () => {
    const polygon = createOccupiedPolygonToPlacementEdge(overlay.frontline, overlay.ukrainePlacementPolygon);
    if (polygon.length < 3) {
      setStatus("Front line needs at least two points before filling occupied territory.");
      return;
    }
    setOverlay((current) => ({
      ...current,
      occupiedPolygons: [polygon],
    }));
    setDraftPolygon([]);
    setStatus("Occupied territory filled from the front line to the outer placement edge.");
  };

  const removeLastPolygon = () => {
    if (mode === "frontline") return;
    setOverlay((current) => ({
      ...current,
      occupiedPolygons: mode === "occupied" ? current.occupiedPolygons.slice(0, -1) : current.occupiedPolygons,
      waterPlacementPolygons: mode === "water" ? current.waterPlacementPolygons.slice(0, -1) : current.waterPlacementPolygons,
    }));
    setStatus(`${modeLabels[mode].title}: last polygon removed.`);
  };

  const clearCurrentLayer = () => {
    if (mode === "frontline") {
      setOverlay((current) => ({ ...current, frontline: [] }));
      setStatus("Front line cleared.");
      return;
    }
    setDraftPolygon([]);
    setOverlay((current) => ({
      ...current,
      occupiedPolygons: mode === "occupied" ? [] : current.occupiedPolygons,
      waterPlacementPolygons: mode === "water" ? [] : current.waterPlacementPolygons,
    }));
    setStatus(`${modeLabels[mode].title}: layer cleared.`);
  };

  const reset = () => {
    resetControlOverlay();
    setOverlay(defaultControlOverlay);
    setDraftPolygon([]);
    setStatus("Reset to default editorial zones. Save to publish this state.");
  };

  const save = async () => {
    if (overlay.frontline.length < 2) {
      setStatus("Front line needs at least two points.");
      return;
    }
    try {
      await saveControlOverlayToServer(basePath, overlay, password);
      saveControlOverlay(overlay);
      setStatus("Saved to server. Return to the map to use the updated placement rules.");
    } catch (error) {
      saveControlOverlay(overlay);
      const message = error instanceof Error ? error.message : "Could not save zones.";
      setStatus(`Saved in this browser, but server save failed: ${message}`);
    }
  };

  if (!authenticated) {
    return (
      <main className="admin-shell admin-shell--login" aria-label="Shieldline admin login">
        <section className="admin-login-card">
          <a className="admin-back-link" href={basePath}>
            <ArrowLeft size={18} />
            Map
          </a>
          <div className="admin-login-card__head">
            <Lock size={26} />
            <div>
              <h1>Shieldline Admin</h1>
              <span>Enter the password before opening zone editing.</span>
            </div>
          </div>
          <label className="admin-password">
            <span>
              <strong>Admin password</strong>
              <small>Matches `SHIELDLINE_ADMIN_PASSWORD` on the server.</small>
            </span>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") void login();
              }}
              autoComplete="current-password"
              autoFocus
            />
          </label>
          <button className="admin-login-button" type="button" onClick={() => void login()} disabled={authChecking}>
            <Lock size={16} />
            {authChecking ? "Checking..." : "Enter admin"}
          </button>
          <section className="admin-status" aria-live="polite">
            {status}
          </section>
        </section>
      </main>
    );
  }

  return (
    <main className="admin-shell" aria-label="Shieldline control zone admin">
      <header className="admin-topbar">
        <a className="admin-back-link" href={basePath}>
          <ArrowLeft size={18} />
          Map
        </a>
        <div>
          <h1>Shieldline Zones</h1>
          <span>Click the map to configure occupied areas, front line, and water-only boat placement.</span>
        </div>
      </header>

      <section className="admin-status" aria-live="polite">
        {status}
      </section>

      <section className="admin-zone-layout">
        <aside className="admin-zone-panel" aria-label="Zone editing controls">
          <div className="admin-mode-tabs" role="tablist" aria-label="Zone mode">
            {(Object.keys(modeLabels) as ZoneMode[]).map((item) => (
              <button
                key={item}
                type="button"
                className={mode === item ? "admin-mode-tab admin-mode-tab--active" : "admin-mode-tab"}
                onClick={() => {
                  setMode(item);
                  setDraftPolygon([]);
                  setStatus(modeLabels[item].help);
                }}
              >
                {modeLabels[item].title}
              </button>
            ))}
          </div>

          <div className="admin-mode-help">
            <MousePointer2 size={18} />
            <span>{modeLabels[mode].help}</span>
          </div>

          <div className="admin-zone-stats">
            <span><b>{overlay.frontline.length}</b> front points</span>
            <span><b>{overlay.occupiedPolygons.length}</b> occupied polygons</span>
            <span><b>{overlay.waterPlacementPolygons.length}</b> water polygons</span>
            <span><b>{draftPolygon.length}</b> draft points</span>
          </div>

          <div className="admin-zone-actions">
            <button type="button" onClick={undoPoint} disabled={mode === "frontline" ? overlay.frontline.length <= 2 : draftPolygon.length === 0}>
              <Undo2 size={16} />
              Undo point
            </button>
            <button type="button" onClick={closePolygon} disabled={mode === "frontline" || draftPolygon.length < 3}>
              Close polygon
            </button>
            <button type="button" onClick={fillOccupiedToPlacementEdge} disabled={overlay.frontline.length < 2}>
              Fill occupied side
            </button>
            <button type="button" onClick={removeLastPolygon} disabled={mode === "frontline"}>
              <Trash2 size={16} />
              Remove last polygon
            </button>
            <button type="button" onClick={clearCurrentLayer}>
              <Trash2 size={16} />
              Clear layer
            </button>
          </div>
        </aside>

        <AdminZoneMap mode={mode} overlay={overlay} draftPolygon={draftPolygon} onMapClick={appendPoint} />
      </section>

      <footer className="admin-actions">
        <button type="button" onClick={reset}>
          <RotateCcw size={16} />
          Reset defaults
        </button>
        <button type="button" onClick={() => void save()}>
          <Save size={16} />
          Save zones
        </button>
      </footer>
    </main>
  );
}
