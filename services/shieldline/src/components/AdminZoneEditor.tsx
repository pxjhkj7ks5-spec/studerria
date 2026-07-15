import { MousePointer2, RotateCcw, Save, Trash2, Undo2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { CircleMarker, MapContainer, Polygon, Polyline, TileLayer, useMapEvents } from "react-leaflet";
import { adminApi } from "../data/adminApi";
import { defaultControlOverlay, saveControlOverlay } from "../data/controlZones";
import type { ControlOverlay } from "../data/controlZones";
import { darkMapTiles } from "../data/mapTiles";
import type { Coordinates } from "../types/game";

type ZoneMode = "occupied" | "water";
const labels = { occupied: "Окуповані території", water: "Водні зони" } satisfies Record<ZoneMode, string>;

function ClickCapture({ onClick }: { onClick: (point: Coordinates) => void }) {
  useMapEvents({ click: ({ latlng }) => onClick({ lat: latlng.lat, lng: latlng.lng }) });
  return null;
}

export function AdminZoneEditor() {
  const [overlay, setOverlay] = useState<ControlOverlay>(defaultControlOverlay);
  const [mode, setMode] = useState<ZoneMode>("occupied");
  const [draft, setDraft] = useState<Coordinates[]>([]);
  const [status, setStatus] = useState("Завантаження зон…");
  useEffect(() => { adminApi.zones().then(({ overlay: remote }) => { if (remote) setOverlay(remote as ControlOverlay); setStatus("Редактор готовий."); }).catch((error) => setStatus(error.message)); }, []);
  const color = mode === "water" ? "#63c7d4" : "#ff625a";
  const positions = useMemo(() => draft.map((point) => [point.lat, point.lng] as [number, number]), [draft]);
  const close = () => {
    if (draft.length < 3) return setStatus("Для полігона потрібно щонайменше три точки.");
    setOverlay((current) => ({ ...current, occupiedPolygons: mode === "occupied" ? [...current.occupiedPolygons, draft] : current.occupiedPolygons, waterPlacementPolygons: mode === "water" ? [...current.waterPlacementPolygons, draft] : current.waterPlacementPolygons }));
    setDraft([]); setStatus("Полігон додано. Збережіть зміни для публікації.");
  };
  const removeLast = () => setOverlay((current) => ({ ...current, occupiedPolygons: mode === "occupied" ? current.occupiedPolygons.slice(0, -1) : current.occupiedPolygons, waterPlacementPolygons: mode === "water" ? current.waterPlacementPolygons.slice(0, -1) : current.waterPlacementPolygons }));
  const save = async () => { await adminApi.saveZones(overlay); saveControlOverlay(overlay); setStatus("Зони збережено на сервері."); };
  return <section className="admin-zones-workspace">
    <div className="admin-zone-tools">
      <div className="admin-segmented">{(Object.keys(labels) as ZoneMode[]).map((item) => <button type="button" className={mode === item ? "is-active" : ""} onClick={() => { setMode(item); setDraft([]); }} key={item}>{labels[item]}</button>)}</div>
      <p><MousePointer2 size={16} /> Натискайте на карту, щоб створити контур. Наступні точки з’єднуються автоматично.</p>
      <dl><div><dt>Окуповані</dt><dd>{overlay.occupiedPolygons.length}</dd></div><div><dt>Водні</dt><dd>{overlay.waterPlacementPolygons.length}</dd></div><div><dt>Точки</dt><dd>{draft.length}</dd></div></dl>
      <div className="admin-zone-buttons"><button type="button" disabled={!draft.length} onClick={() => setDraft((current) => current.slice(0, -1))}><Undo2 size={15} /> Назад</button><button type="button" disabled={draft.length < 3} onClick={close}>Замкнути</button><button type="button" onClick={removeLast}><Trash2 size={15} /> Останній полігон</button><button type="button" onClick={() => { setOverlay(defaultControlOverlay); setDraft([]); }}><RotateCcw size={15} /> Типові зони</button><button type="button" className="admin-primary" onClick={() => void save()}><Save size={15} /> Зберегти</button></div>
      <small aria-live="polite">{status}</small>
    </div>
    <MapContainer center={[48.7, 31.4]} zoom={6} minZoom={5} maxZoom={12} preferCanvas className="admin-zone-map" scrollWheelZoom>
      <ClickCapture onClick={(point) => setDraft((current) => [...current, point])} />
      <TileLayer url={darkMapTiles.url} attribution={darkMapTiles.attribution} className={darkMapTiles.className} />
      {overlay.waterPlacementPolygons.map((polygon, index) => <Polygon key={`w-${index}`} positions={polygon.map((p) => [p.lat, p.lng])} pathOptions={{ color: "#63c7d4", fillColor: "#63c7d4", fillOpacity: .08, opacity: .55, weight: 1.2 }} />)}
      {overlay.occupiedPolygons.map((polygon, index) => <Polygon key={`o-${index}`} positions={polygon.map((p) => [p.lat, p.lng])} pathOptions={{ color: "#ff625a", fillColor: "#ff625a", fillOpacity: .15, opacity: .58, weight: 1.3, dashArray: "5 5" }} />)}
      {draft.length ? <><Polyline positions={positions} pathOptions={{ color, weight: 2.5, dashArray: "3 5" }} />{draft.map((p, index) => <CircleMarker key={`${p.lat}-${p.lng}-${index}`} center={[p.lat, p.lng]} radius={5} pathOptions={{ color: "#fff", fillColor: color, fillOpacity: .95 }} />)}</> : null}
    </MapContainer>
  </section>;
}
