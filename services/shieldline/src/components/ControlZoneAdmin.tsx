import { ArrowLeft, Lock, MousePointer2, RotateCcw, Save, Trash2, Undo2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { CircleMarker, MapContainer, Polygon, Polyline, TileLayer, useMapEvents } from "react-leaflet";
import {
  defaultControlOverlay,
  getControlOverlay,
  resetControlOverlay,
  saveControlOverlay,
  saveControlOverlayToServer,
  verifyControlOverlayAdminPassword,
} from "../data/controlZones";
import type { ControlOverlay } from "../data/controlZones";
import { darkMapTiles } from "../data/mapTiles";
import type { Coordinates } from "../types/game";

type ZoneMode = "occupied" | "water";

const mapCenter: [number, number] = [48.7, 31.4];

const modeLabels: Record<ZoneMode, { title: string; help: string }> = {
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

const ukrainePlacementStyle = { color: "#f6c547", fillColor: "#f6c547", fillOpacity: 0.025, opacity: 0.22, weight: 1 };
const waterPlacementStyle = { color: "#718796", fillColor: "#586f80", fillOpacity: 0.085, opacity: 0.4, weight: 1.2, dashArray: "4 7" };
const occupiedZoneStyle = { color: "#ff4f4f", fillColor: "#ff4f4f", fillOpacity: 0.16, opacity: 0.56, weight: 1.4, dashArray: "6 5" };

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
  const draftColor = mode === "water" ? "#718796" : "#ff625a";
  const ukrainePlacementPositions = useMemo(
    () => overlay.ukrainePlacementPolygons.map((polygon) => toPositions(polygon)),
    [overlay.ukrainePlacementPolygons],
  );
  const waterPlacementPositions = useMemo(
    () => overlay.waterPlacementPolygons.map((polygon) => toPositions(polygon)),
    [overlay.waterPlacementPolygons],
  );
  const occupiedZonePositions = useMemo(
    () => overlay.occupiedPolygons.map((polygon) => toPositions(polygon)),
    [overlay.occupiedPolygons],
  );
  const draftPositions = useMemo(() => toPositions(draftPolygon), [draftPolygon]);

  return (
    <MapContainer
      center={mapCenter}
      zoom={6}
      minZoom={5}
      maxZoom={12}
      zoomControl
      attributionControl
      preferCanvas
      zoomAnimation
      markerZoomAnimation
      zoomSnap={0.25}
      zoomDelta={0.5}
      wheelPxPerZoomLevel={140}
      wheelDebounceTime={35}
      zoomAnimationThreshold={4}
      fadeAnimation={false}
      className="admin-map"
      scrollWheelZoom
    >
      <ClickCapture onClick={onMapClick} />
      <TileLayer url={darkMapTiles.url} attribution={darkMapTiles.attribution} className={darkMapTiles.className} />
      {ukrainePlacementPositions.map((positions, index) => (
        <Polygon
          key={`ukraine-placement-${index}`}
          positions={positions}
          pathOptions={ukrainePlacementStyle}
        />
      ))}
      {waterPlacementPositions.map((positions, index) => (
        <Polygon
          key={`water-${index}`}
          positions={positions}
          pathOptions={waterPlacementStyle}
        />
      ))}
      {occupiedZonePositions.map((positions, index) => (
        <Polygon
          key={`occupied-${index}`}
          positions={positions}
          pathOptions={occupiedZoneStyle}
        />
      ))}
      {draftPolygon.length ? (
        <>
          <Polyline positions={draftPositions} pathOptions={{ color: draftColor, weight: 2.5, opacity: 0.92, dashArray: "3 5" }} />
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
  const [mode, setMode] = useState<ZoneMode>("occupied");
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
    setDraftPolygon((current) => [...current, point]);
    setStatus(`${modeLabels[mode].title}: draft point added.`);
  };

  const undoPoint = () => {
    setDraftPolygon((current) => current.slice(0, -1));
    setStatus("Last draft point removed.");
  };

  const closePolygon = () => {
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

  const removeLastPolygon = () => {
    setOverlay((current) => ({
      ...current,
      occupiedPolygons: mode === "occupied" ? current.occupiedPolygons.slice(0, -1) : current.occupiedPolygons,
      waterPlacementPolygons: mode === "water" ? current.waterPlacementPolygons.slice(0, -1) : current.waterPlacementPolygons,
    }));
    setStatus(`${modeLabels[mode].title}: last polygon removed.`);
  };

  const clearCurrentLayer = () => {
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
          <span>Click the map to configure occupied areas and water-only boat placement.</span>
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
            <span><b>{overlay.occupiedPolygons.length}</b> occupied polygons</span>
            <span><b>{overlay.waterPlacementPolygons.length}</b> water polygons</span>
            <span><b>{draftPolygon.length}</b> draft points</span>
          </div>

          <div className="admin-zone-actions">
            <button type="button" onClick={undoPoint} disabled={draftPolygon.length === 0}>
              <Undo2 size={16} />
              Undo point
            </button>
            <button type="button" onClick={closePolygon} disabled={draftPolygon.length < 3}>
              Close polygon
            </button>
            <button type="button" onClick={removeLastPolygon}>
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
