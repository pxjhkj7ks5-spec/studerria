import L from "leaflet";
import { Circle, Marker, Polygon, Polyline, TileLayer, Tooltip, MapContainer, useMap, useMapEvents } from "react-leaflet";
import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { carrierSprites, launchSprites, markerSprites, threatSprites, unitSprites } from "../assets/sprites/spriteCatalog";
import { getControlOverlay } from "../data/controlZones";
import { darkMapTiles } from "../data/mapTiles";
import { getUnitDefinition } from "../data/units";
import { CITY_PLACEMENT_EXCLUSION_KM } from "../game/placementRules";
import { useGameStore } from "../store/useGameStore";
import type {
  City,
  CarrierTrack,
  DefenseBattery,
  ImpactMarker,
  InterceptorShot,
  LaunchSector,
  LiveThreat,
  SupplyRoute,
} from "../types/game";

const mapCenter: [number, number] = [48.7, 31.4];
const CHUNK_SIZE_DEG = 2;
const VIEWPORT_PAD_RATIO = 0.42;
const VIEWPORT_MOVE_UPDATE_MS = 280;
const LOW_FPS_THRESHOLD = 42;
const RECOVERED_FPS_THRESHOLD = 52;
const MAX_RENDERED_IMPACTS_LOW_FPS = 10;

interface RenderBounds {
  north: number;
  south: number;
  east: number;
  west: number;
  zoom: number;
  chunkKeys: Set<string>;
  key: string;
}

interface RenderCounts {
  activeObjects: number;
  renderedObjects: number;
  activeChunks: number;
  cachedChunks: number;
}

interface PerformanceStats {
  fps: number;
  frameMs: number;
  memoryMb: number | null;
  quality: "full" | "reduced";
}

const cityIconCache = new Map<string, L.DivIcon>();
const batteryIconCache = new Map<string, L.DivIcon>();
const shotIconCache = new Map<string, L.DivIcon>();
const impactIconCache = new Map<string, L.DivIcon>();
const launchIconCache = new Map<string, L.DivIcon>();
const carrierIconCache = new Map<string, L.DivIcon>();
const threatIconCache = new Map<string, L.DivIcon>();

function threatPosition(threat: LiveThreat) {
  return {
    lat: threat.origin.lat + (threat.target.lat - threat.origin.lat) * threat.progress,
    lng: threat.origin.lng + (threat.target.lng - threat.origin.lng) * threat.progress,
  };
}

function interpolatedThreatPosition(threat: LiveThreat, elapsedSinceSyncMs: number) {
  const progress = Math.min(1, threat.progress + threat.speed * elapsedSinceSyncMs);
  return {
    lat: threat.origin.lat + (threat.target.lat - threat.origin.lat) * progress,
    lng: threat.origin.lng + (threat.target.lng - threat.origin.lng) * progress,
  };
}

function shotPosition(shot: InterceptorShot) {
  return {
    lat: shot.from.lat + (shot.to.lat - shot.from.lat) * shot.progress,
    lng: shot.from.lng + (shot.to.lng - shot.from.lng) * shot.progress,
  };
}

function interpolatedShotPosition(shot: InterceptorShot, elapsedSinceSyncMs: number) {
  const progress = Math.min(1, shot.progress + shot.speed * elapsedSinceSyncMs);
  return {
    lat: shot.from.lat + (shot.to.lat - shot.from.lat) * progress,
    lng: shot.from.lng + (shot.to.lng - shot.from.lng) * progress,
  };
}

function toPositions(points: Array<{ lat: number; lng: number }>): [number, number][] {
  return points.map((point) => [point.lat, point.lng]);
}

function chunkCoord(value: number) {
  return Math.floor(value / CHUNK_SIZE_DEG);
}

function chunkKeyForPoint(point: { lat: number; lng: number }) {
  return `${chunkCoord(point.lat)}:${chunkCoord(point.lng)}`;
}

function chunkKeysForBounds(bounds: Pick<RenderBounds, "north" | "south" | "east" | "west">) {
  const keys = new Set<string>();
  const south = Math.min(bounds.south, bounds.north);
  const north = Math.max(bounds.south, bounds.north);
  const west = Math.min(bounds.west, bounds.east);
  const east = Math.max(bounds.west, bounds.east);
  for (let lat = chunkCoord(south) - 1; lat <= chunkCoord(north) + 1; lat += 1) {
    for (let lng = chunkCoord(west) - 1; lng <= chunkCoord(east) + 1; lng += 1) {
      keys.add(`${lat}:${lng}`);
    }
  }
  return keys;
}

function createRenderBounds(map: L.Map): RenderBounds {
  const padded = map.getBounds().pad(VIEWPORT_PAD_RATIO);
  const north = padded.getNorth();
  const south = padded.getSouth();
  const east = padded.getEast();
  const west = padded.getWest();
  const zoom = map.getZoom();
  const chunkKeys = chunkKeysForBounds({ north, south, east, west });
  return {
    north,
    south,
    east,
    west,
    zoom,
    chunkKeys,
    key: `${north.toFixed(2)}:${south.toFixed(2)}:${east.toFixed(2)}:${west.toFixed(2)}:${zoom.toFixed(2)}`,
  };
}

function pointInBounds(point: { lat: number; lng: number }, bounds: RenderBounds | null, radiusDeg = 0) {
  if (!bounds) return true;
  if (!bounds.chunkKeys.has(chunkKeyForPoint(point))) return false;
  return point.lat >= bounds.south - radiusDeg
    && point.lat <= bounds.north + radiusDeg
    && point.lng >= bounds.west - radiusDeg
    && point.lng <= bounds.east + radiusDeg;
}

function lineInBounds(from: { lat: number; lng: number }, to: { lat: number; lng: number }, bounds: RenderBounds | null) {
  if (!bounds) return true;
  if (pointInBounds(from, bounds) || pointInBounds(to, bounds)) return true;
  const minLat = Math.min(from.lat, to.lat);
  const maxLat = Math.max(from.lat, to.lat);
  const minLng = Math.min(from.lng, to.lng);
  const maxLng = Math.max(from.lng, to.lng);
  return maxLat >= bounds.south && minLat <= bounds.north && maxLng >= bounds.west && minLng <= bounds.east;
}

function polygonBounds(points: Array<{ lat: number; lng: number }>) {
  let north = -Infinity;
  let south = Infinity;
  let east = -Infinity;
  let west = Infinity;
  for (const point of points) {
    north = Math.max(north, point.lat);
    south = Math.min(south, point.lat);
    east = Math.max(east, point.lng);
    west = Math.min(west, point.lng);
  }
  return { north, south, east, west, chunkKeys: chunkKeysForBounds({ north, south, east, west }) };
}

function boundsIntersect(
  shape: { north: number; south: number; east: number; west: number; chunkKeys?: Set<string> },
  bounds: RenderBounds | null,
) {
  if (!bounds) return true;
  if (shape.chunkKeys) {
    let hasSharedChunk = false;
    for (const key of shape.chunkKeys) {
      if (bounds.chunkKeys.has(key)) {
        hasSharedChunk = true;
        break;
      }
    }
    if (!hasSharedChunk) return false;
  }
  return shape.north >= bounds.south && shape.south <= bounds.north && shape.east >= bounds.west && shape.west <= bounds.east;
}

const occupiedZoneStyle = { color: "#ff4f4f", fillColor: "#ff4f4f", fillOpacity: 0.13, opacity: 0.52, weight: 1.4, dashArray: "6 5" };

function makeCityIcon(city: City) {
  const alert = city.alertState || "calm";
  const hp = Math.round(city.infrastructure);
  const key = `${city.id}:${alert}:${hp}`;
  const cached = cityIconCache.get(key);
  if (cached) return cached;
  const icon = L.divIcon({
    className: "",
    html: `<span class="city-marker-label city-marker-label--${alert}"><span class="map-marker map-marker--city map-marker--city-${alert}" aria-hidden="true"></span><b>${hp}% 🛡️</b></span>`,
    iconSize: [58, 42],
    iconAnchor: [29, 8],
  });
  cityIconCache.set(key, icon);
  return icon;
}

function imageMarkerHtml(src: string, className: string) {
  return `<span class="map-marker map-marker--image ${className}"><img src="${src}" alt="" draggable="false" /></span>`;
}

function threatTone(threat: LiveThreat) {
  if (threat.kind === "decoy") return "decoy";
  if (threat.status === "engaged") return "confirmed";
  return "uncertain";
}

function threatRouteColor(tone: ReturnType<typeof threatTone>) {
  if (tone === "confirmed") return "#ff3535";
  if (tone === "decoy") return "#b997ff";
  return "#ff3535";
}

function coverageTone(unit: ReturnType<typeof getUnitDefinition>, selected: boolean) {
  if (unit.engagementMode === "detect") {
    return selected
      ? { color: "#72ff9d", fill: "#52e980", fillOpacity: 0.14, opacity: 0.82, weight: 2.4 }
      : { color: "#52e980", fill: "#36d977", fillOpacity: 0.075, opacity: 0.58, weight: 1.5 };
  }
  return selected
    ? { color: "#73e4ff", fill: "#55d7ff", fillOpacity: 0.13, opacity: 0.78, weight: 2.2 }
    : { color: "#55d7ff", fill: "#27bfff", fillOpacity: 0.06, opacity: 0.48, weight: 1.35 };
}

function makeBatteryIcon(battery: DefenseBattery, selected: boolean) {
  const key = `${battery.kind}:${battery.status}:${selected}`;
  const cached = batteryIconCache.get(key);
  if (cached) return cached;
  const icon = L.divIcon({
    className: "",
    html: imageMarkerHtml(unitSprites[battery.kind], `map-marker--battery map-marker--unit-${battery.status} ${selected ? "map-marker--selected" : ""}`),
    iconSize: [22, 22],
    iconAnchor: [11, 11],
  });
  batteryIconCache.set(key, icon);
  return icon;
}

function makeThreatIcon(threat: LiveThreat) {
  const tone = threatTone(threat);
  const targetHeading = Math.round(threat.headingDeg - 90);
  const key = `${threat.kind}:${tone}:${Math.round(threat.confidence / 10)}:${targetHeading}`;
  const cached = threatIconCache.get(key);
  if (cached) return cached;
  const icon = L.divIcon({
    className: "",
    html: `<span class="threat-marker-wrap threat-marker-wrap--compact" style="--target-heading:${targetHeading}deg"><span class="target-sprite target-sprite--${tone}"><img src="${threatSprites[threat.kind]}" alt="" draggable="false" /></span></span>`,
    iconSize: [32, 32],
    iconAnchor: [16, 16],
  });
  threatIconCache.set(key, icon);
  return icon;
}

function makeShotIcon() {
  const cached = shotIconCache.get("shot");
  if (cached) return cached;
  const icon = L.divIcon({
    className: "",
    html: imageMarkerHtml(markerSprites.interceptorShot, "map-marker--shot"),
    iconSize: [14, 14],
    iconAnchor: [7, 7],
  });
  shotIconCache.set("shot", icon);
  return icon;
}

function makeImpactIcon(marker: ImpactMarker) {
  const key = marker.tone;
  const cached = impactIconCache.get(key);
  if (cached) return cached;
  const icon = L.divIcon({
    className: "",
    html: imageMarkerHtml(marker.tone === "impact" ? markerSprites.impactEvent : markerSprites.interceptedThreat, `map-marker--${marker.tone}`),
    iconSize: [20, 20],
    iconAnchor: [10, 10],
  });
  impactIconCache.set(key, icon);
  return icon;
}

function makeLaunchIcon(sector: LaunchSector) {
  const category = sector.category || "drone";
  const state = sector.state || "idle";
  const hasDirection = sector.targetHeadingDeg !== undefined && (state === "warning" || state === "launching");
  const directionDeg = hasDirection ? Math.round(sector.targetHeadingDeg! - 90) : 0;
  const key = `${category}:${state}:${hasDirection ? directionDeg : "none"}`;
  const cached = launchIconCache.get(key);
  if (cached) return cached;
  const icon = L.divIcon({
    className: "",
    html: `<span class="launch-marker-shell launch-marker-shell--${state} ${hasDirection ? "launch-marker-shell--directed" : ""}" style="--launch-heading:${directionDeg}deg"><span class="launch-direction" aria-hidden="true"></span><span class="launch-ripple" aria-hidden="true"></span>${imageMarkerHtml(launchSprites[category], `map-marker--launch map-marker--launch-${state}`)}</span>`,
    iconSize: [58, 58],
    iconAnchor: [29, 29],
  });
  launchIconCache.set(key, icon);
  return icon;
}

function makeCarrierIcon(carrier: CarrierTrack) {
  const cached = carrierIconCache.get(carrier.kind);
  if (cached) return cached;
  const icon = L.divIcon({
    className: "",
    html: imageMarkerHtml(carrierSprites[carrier.kind], "map-marker--carrier"),
    iconSize: [20, 20],
    iconAnchor: [10, 10],
  });
  carrierIconCache.set(carrier.kind, icon);
  return icon;
}

function routeColor(route: SupplyRoute) {
  if (route.status === "well-supplied") return "#78dd9a";
  if (route.status === "undersupplied") return "#ff6e6e";
  return "#f2c865";
}

function MapClickPlacement() {
  const placementKind = useGameStore((state) => state.placementKind);
  const placeSelectedBattery = useGameStore((state) => state.placeSelectedBattery);

  useMapEvents({
    click(event) {
      if (!placementKind) return;
      placeSelectedBattery({ lat: event.latlng.lat, lng: event.latlng.lng });
    },
  });

  return null;
}

function MapViewportTracker({
  onChange,
  onZoomingChange,
}: {
  onChange: (bounds: RenderBounds) => void;
  onZoomingChange: (zooming: boolean) => void;
}) {
  const frameRef = useRef(0);
  const moveTimeoutRef = useRef<number | null>(null);
  const lastMoveUpdateRef = useRef(0);
  const zoomingRef = useRef(false);
  const lastKeyRef = useRef("");
  const map = useMapEvents({
    move() {
      scheduleMoveUpdate();
    },
    zoomstart() {
      zoomingRef.current = true;
      onZoomingChange(true);
      clearMoveTimeout();
    },
    moveend() {
      scheduleImmediateUpdate();
    },
    zoomend() {
      zoomingRef.current = false;
      onZoomingChange(false);
      scheduleImmediateUpdate();
    },
    resize() {
      scheduleImmediateUpdate();
    },
  });

  function clearMoveTimeout() {
    if (moveTimeoutRef.current === null) return;
    window.clearTimeout(moveTimeoutRef.current);
    moveTimeoutRef.current = null;
  }

  function scheduleMoveUpdate() {
    if (zoomingRef.current || moveTimeoutRef.current !== null) return;
    const elapsed = performance.now() - lastMoveUpdateRef.current;
    const delay = Math.max(0, VIEWPORT_MOVE_UPDATE_MS - elapsed);
    moveTimeoutRef.current = window.setTimeout(() => {
      moveTimeoutRef.current = null;
      scheduleViewportFrame();
    }, delay);
  }

  function scheduleImmediateUpdate() {
    clearMoveTimeout();
    scheduleViewportFrame();
  }

  function scheduleViewportFrame() {
    window.cancelAnimationFrame(frameRef.current);
    frameRef.current = window.requestAnimationFrame(() => {
      const next = createRenderBounds(map);
      if (next.key === lastKeyRef.current) return;
      lastKeyRef.current = next.key;
      lastMoveUpdateRef.current = performance.now();
      onChange(next);
    });
  }

  useEffect(() => {
    scheduleImmediateUpdate();
    return () => {
      clearMoveTimeout();
      window.cancelAnimationFrame(frameRef.current);
    };
  }, []);

  return null;
}

interface MovingObjectsLayerProps {
  threats: LiveThreat[];
  shots: InterceptorShot[];
  impacts: ImpactMarker[];
  elapsedMs: number;
  mapMode: string;
  reducedQuality: boolean;
}

function MovingObjectsLayer({ threats, shots, impacts, elapsedMs, mapMode, reducedQuality }: MovingObjectsLayerProps) {
  const map = useMap();
  const threatGroupRef = useRef<L.LayerGroup | null>(null);
  const shotGroupRef = useRef<L.LayerGroup | null>(null);
  const impactGroupRef = useRef<L.LayerGroup | null>(null);
  const threatPoolRef = useRef(new Map<string, { marker: L.Marker; route: L.Polyline | null }>());
  const shotPoolRef = useRef(new Map<string, { marker: L.Marker; route: L.Polyline }>());
  const impactPoolRef = useRef(new Map<string, L.Marker>());
  const latestRef = useRef({ threats, shots, impacts, elapsedMs, mapMode, reducedQuality });
  const syncAtRef = useRef(0);
  const lastSyncedElapsedMsRef = useRef<number | null>(null);
  const mapMovingRef = useRef(false);
  const frameRef = useRef(0);

  useEffect(() => {
    const threatGroup = L.layerGroup().addTo(map);
    const shotGroup = L.layerGroup().addTo(map);
    const impactGroup = L.layerGroup().addTo(map);
    threatGroupRef.current = threatGroup;
    shotGroupRef.current = shotGroup;
    impactGroupRef.current = impactGroup;

    const pauseMapAnimation = () => {
      mapMovingRef.current = true;
    };
    const resumeMapAnimation = () => {
      mapMovingRef.current = false;
    };
    map.on("movestart", pauseMapAnimation);
    map.on("zoomstart", pauseMapAnimation);
    map.on("moveend", resumeMapAnimation);
    map.on("zoomend", resumeMapAnimation);

    const animate = () => {
      if (!mapMovingRef.current) {
        const elapsedSinceSync = Math.max(0, performance.now() - syncAtRef.current);
        const latest = latestRef.current;
        for (const threat of latest.threats) {
          const pooled = threatPoolRef.current.get(threat.id);
          if (!pooled) continue;
          const current = interpolatedThreatPosition(threat, elapsedSinceSync);
          pooled.marker.setLatLng([current.lat, current.lng]);
          if (pooled.route) {
            pooled.route.setLatLngs([[current.lat, current.lng], [threat.target.lat, threat.target.lng]]);
          }
        }
        for (const shot of latest.shots) {
          const pooled = shotPoolRef.current.get(shot.id);
          if (!pooled) continue;
          const current = interpolatedShotPosition(shot, elapsedSinceSync);
          pooled.marker.setLatLng([current.lat, current.lng]);
          pooled.route.setLatLngs([[shot.from.lat, shot.from.lng], [current.lat, current.lng]]);
        }
      }
      frameRef.current = window.requestAnimationFrame(animate);
    };
    frameRef.current = window.requestAnimationFrame(animate);

    return () => {
      window.cancelAnimationFrame(frameRef.current);
      map.off("movestart", pauseMapAnimation);
      map.off("zoomstart", pauseMapAnimation);
      map.off("moveend", resumeMapAnimation);
      map.off("zoomend", resumeMapAnimation);
      threatGroup.remove();
      shotGroup.remove();
      impactGroup.remove();
      threatPoolRef.current.clear();
      shotPoolRef.current.clear();
      impactPoolRef.current.clear();
      threatGroupRef.current = null;
      shotGroupRef.current = null;
      impactGroupRef.current = null;
    };
  }, [map]);

  useEffect(() => {
    latestRef.current = { threats, shots, impacts, elapsedMs, mapMode, reducedQuality };
    if (lastSyncedElapsedMsRef.current !== elapsedMs) {
      lastSyncedElapsedMsRef.current = elapsedMs;
      syncAtRef.current = performance.now();
    }
    const elapsedSinceSync = Math.max(0, performance.now() - syncAtRef.current);
    const threatGroup = threatGroupRef.current;
    const shotGroup = shotGroupRef.current;
    const impactGroup = impactGroupRef.current;
    if (!threatGroup || !shotGroup || !impactGroup) return;

    const threatIds = new Set(threats.map((threat) => threat.id));
    for (const [id, pooled] of threatPoolRef.current) {
      if (!threatIds.has(id)) {
        pooled.marker.remove();
        pooled.route?.remove();
        threatPoolRef.current.delete(id);
      }
    }
    for (const threat of threats) {
      const tone = threatTone(threat);
      const routeAllowed = threat.confidence >= (reducedQuality ? 72 : 58) && (!reducedQuality || mapMode === "threats");
      let pooled = threatPoolRef.current.get(threat.id);
      const current = interpolatedThreatPosition(threat, elapsedSinceSync);
      if (!pooled) {
        pooled = {
          marker: L.marker([current.lat, current.lng], { icon: makeThreatIcon(threat), interactive: false }).addTo(threatGroup),
          route: null,
        };
        threatPoolRef.current.set(threat.id, pooled);
      } else {
        pooled.marker.setIcon(makeThreatIcon(threat));
      }
      if (routeAllowed && !pooled.route) {
        pooled.route = L.polyline([[current.lat, current.lng], [threat.target.lat, threat.target.lng]], {
          color: threatRouteColor(tone),
          weight: mapMode === "threats" ? 3 : 2,
          opacity: mapMode === "coverage" ? 0.44 : 0.72,
          dashArray: tone === "confirmed" ? "10 4" : "6 6",
          interactive: false,
        }).addTo(threatGroup);
      } else if (!routeAllowed && pooled.route) {
        pooled.route.remove();
        pooled.route = null;
      } else if (pooled.route) {
        pooled.route.setStyle({
          color: threatRouteColor(tone),
          weight: mapMode === "threats" ? 3 : 2,
          opacity: mapMode === "coverage" ? 0.44 : 0.72,
          dashArray: tone === "confirmed" ? "10 4" : "6 6",
        });
      }
    }

    const shotIds = new Set(shots.map((shot) => shot.id));
    for (const [id, pooled] of shotPoolRef.current) {
      if (!shotIds.has(id)) {
        pooled.marker.remove();
        pooled.route.remove();
        shotPoolRef.current.delete(id);
      }
    }
    for (const shot of shots) {
      let pooled = shotPoolRef.current.get(shot.id);
      const current = interpolatedShotPosition(shot, elapsedSinceSync);
      const pathOptions = {
        color: shot.style === "gun" ? "#ffd466" : shot.style === "drone" ? "#7ee7ff" : shot.style === "ew" ? "#b58cff" : "#ffef9a",
        weight: shot.style === "gun" ? 2 : 1,
        opacity: reducedQuality ? 0.52 : 0.74,
        dashArray: shot.style === "missile" ? "8 5" : shot.style === "gun" ? "2 7" : "4 5",
        interactive: false,
      };
      if (!pooled) {
        pooled = {
          marker: L.marker([current.lat, current.lng], { icon: makeShotIcon(), interactive: false }).addTo(shotGroup),
          route: L.polyline([[shot.from.lat, shot.from.lng], [current.lat, current.lng]], pathOptions).addTo(shotGroup),
        };
        shotPoolRef.current.set(shot.id, pooled);
      } else {
        pooled.route.setStyle(pathOptions);
      }
    }

    const renderedImpacts = reducedQuality ? impacts.slice(0, MAX_RENDERED_IMPACTS_LOW_FPS) : impacts;
    const impactIds = new Set(renderedImpacts.map((impact) => impact.id));
    for (const [id, marker] of impactPoolRef.current) {
      if (!impactIds.has(id)) {
        marker.remove();
        impactPoolRef.current.delete(id);
      }
    }
    for (const impact of renderedImpacts) {
      if (!impactPoolRef.current.has(impact.id)) {
        impactPoolRef.current.set(
          impact.id,
          L.marker([impact.position.lat, impact.position.lng], { icon: makeImpactIcon(impact), interactive: false }).addTo(impactGroup),
        );
      }
    }
  }, [threats, shots, impacts, elapsedMs, mapMode, reducedQuality]);

  return null;
}

function usePerformanceStats(renderCounts: RenderCounts): PerformanceStats {
  const [stats, setStats] = useState<PerformanceStats>({ fps: 60, frameMs: 16.7, memoryMb: null, quality: "full" });
  const statsRef = useRef(stats);

  useEffect(() => {
    statsRef.current = stats;
  }, [stats]);

  useEffect(() => {
    let frameId = 0;
    let frames = 0;
    let lastFrame = performance.now();
    let lastReport = lastFrame;
    const loop = (timestamp: number) => {
      frames += 1;
      const frameMs = timestamp - lastFrame;
      lastFrame = timestamp;
      if (timestamp - lastReport >= 500) {
        const fps = Math.round((frames * 1000) / (timestamp - lastReport));
        const quality = fps < LOW_FPS_THRESHOLD
          ? "reduced"
          : fps > RECOVERED_FPS_THRESHOLD
            ? "full"
            : statsRef.current.quality;
        const memory = (performance as Performance & { memory?: { usedJSHeapSize: number } }).memory;
        const memoryMb = memory ? Math.round(memory.usedJSHeapSize / 1024 / 1024) : null;
        setStats({ fps, frameMs: Math.round(frameMs * 10) / 10, memoryMb, quality });
        frames = 0;
        lastReport = timestamp;
      }
      frameId = window.requestAnimationFrame(loop);
    };
    frameId = window.requestAnimationFrame(loop);
    return () => window.cancelAnimationFrame(frameId);
  }, [renderCounts.activeObjects, renderCounts.renderedObjects]);

  return stats;
}

function PerformanceOverlay({ stats, counts }: { stats: PerformanceStats; counts: RenderCounts }) {
  return (
    <aside className={`perf-overlay perf-overlay--${stats.quality}`} aria-label="Shieldline performance monitor">
      <span><b>{stats.fps}</b> FPS</span>
      <span><b>{stats.frameMs}</b> ms</span>
      <span><b>{counts.activeObjects}</b> active</span>
      <span><b>{counts.renderedObjects}</b> rendered</span>
      <span><b>{counts.activeChunks}</b> chunks</span>
      <span><b>{counts.cachedChunks}</b> cache</span>
      <span><b>{stats.memoryMb === null ? "n/a" : `${stats.memoryMb}MB`}</b> mem</span>
      <span><b>local</b> net</span>
    </aside>
  );
}

export function TacticalMap() {
  const game = useGameStore((state) => state.game);
  const selectedBatteryId = useGameStore((state) => state.selectedBatteryId);
  const mapMode = useGameStore((state) => state.mapMode);
  const placementKind = useGameStore((state) => state.placementKind);
  const setSelectedBattery = useGameStore((state) => state.setSelectedBattery);
  const [renderBounds, setRenderBounds] = useState<RenderBounds | null>(null);
  const [isMapZooming, setIsMapZooming] = useState(false);
  const radiusOverlayRenderer = useMemo(() => L.svg({ padding: 0.6 }), []);
  const chunkCacheRef = useRef(new Set<string>());
  const [cachedChunkCount, setCachedChunkCount] = useState(0);
  const controlOverlay = useMemo(() => getControlOverlay(), []);
  const occupiedZonePolygons = useMemo(
    () => controlOverlay.occupiedPolygons.map((polygon) => ({
      positions: toPositions(polygon),
      bounds: polygonBounds(polygon),
    })),
    [controlOverlay],
  );

  const visibleCities = useMemo(
    () => game.cities.filter((city) => pointInBounds(city.coordinates, renderBounds)),
    [game.cities, renderBounds],
  );
  const cityMarkers = useMemo(
    () => visibleCities.map((city) => ({
      city,
      icon: makeCityIcon(city),
    })),
    [visibleCities],
  );
  const visibleOccupiedZonePolygons = useMemo(
    () => occupiedZonePolygons.filter((polygon) => boundsIntersect(polygon.bounds, renderBounds)),
    [occupiedZonePolygons, renderBounds],
  );
  const visibleLaunchSectors = useMemo(
    () => game.launchSectors.filter((sector) => pointInBounds(sector.coordinates, renderBounds)),
    [game.launchSectors, renderBounds],
  );
  const visibleCarriers = useMemo(
    () => game.carriers.filter((carrier) => pointInBounds(carrier.position, renderBounds)),
    [game.carriers, renderBounds],
  );
  const visibleBatteries = useMemo(
    () => game.batteries.filter((battery) => pointInBounds(battery.position, renderBounds, Math.max(0.15, battery.coverageRadius * 0.15))),
    [game.batteries, renderBounds],
  );
  const visibleCoverageBatteries = useMemo(
    () => mapMode === "threats" ? [] : game.batteries.filter((battery) => pointInBounds(battery.position, renderBounds, battery.coverageRadius)),
    [game.batteries, mapMode, renderBounds],
  );
  const visibleRoutes = useMemo(
    () => mapMode === "logistics" ? game.logistics.routes.filter((route) => lineInBounds(route.from, route.to, renderBounds)) : [],
    [game.logistics.routes, mapMode, renderBounds],
  );
  const visibleThreats = useMemo(
    () => game.liveThreats.filter((threat) => threat.revealed && lineInBounds(threatPosition(threat), threat.target, renderBounds)),
    [game.liveThreats, renderBounds],
  );
  const visibleShots = useMemo(
    () => game.interceptorShots.filter((shot) => lineInBounds(shot.from, shotPosition(shot), renderBounds)),
    [game.interceptorShots, renderBounds],
  );
  const visibleImpactMarkers = useMemo(
    () => game.impactMarkers.filter((marker) => pointInBounds(marker.position, renderBounds)),
    [game.impactMarkers, renderBounds],
  );
  useEffect(() => {
    if (!renderBounds) return;
    for (const key of renderBounds.chunkKeys) {
      chunkCacheRef.current.add(key);
    }
    setCachedChunkCount(chunkCacheRef.current.size);
  }, [renderBounds?.key]);
  const renderCounts = useMemo<RenderCounts>(() => {
    const activeObjects = game.cities.length
      + game.launchSectors.length
      + game.carriers.length
      + game.batteries.length
      + game.liveThreats.length
      + game.interceptorShots.length
      + game.impactMarkers.length
      + (mapMode === "logistics" ? game.logistics.routes.length : 0);
    const renderedObjects = visibleCities.length
      + visibleLaunchSectors.length
      + visibleCarriers.length
      + visibleBatteries.length
      + visibleThreats.length
      + visibleShots.length
      + visibleImpactMarkers.length
      + visibleCoverageBatteries.length
      + visibleRoutes.length
      + visibleOccupiedZonePolygons.length;
    return {
      activeObjects,
      renderedObjects,
      activeChunks: renderBounds?.chunkKeys.size || 0,
      cachedChunks: cachedChunkCount,
    };
  }, [
    cachedChunkCount,
    game.cities.length,
    game.launchSectors.length,
    game.carriers.length,
    game.batteries.length,
    game.liveThreats.length,
    game.interceptorShots.length,
    game.impactMarkers.length,
    game.logistics.routes.length,
    mapMode,
    renderBounds,
    visibleBatteries.length,
    visibleCarriers.length,
    visibleCities.length,
    visibleCoverageBatteries.length,
    visibleImpactMarkers.length,
    visibleLaunchSectors.length,
    visibleOccupiedZonePolygons.length,
    visibleRoutes.length,
    visibleShots.length,
    visibleThreats.length,
  ]);
  const performanceStats = usePerformanceStats(renderCounts);
  const reducedQuality = performanceStats.quality === "reduced";

  return (
    <>
      <MapContainer
        center={mapCenter}
        zoom={6}
        minZoom={5}
        maxZoom={12}
        zoomControl={false}
        attributionControl
        preferCanvas
        zoomAnimation
        markerZoomAnimation
        inertia
        inertiaDeceleration={2400}
        easeLinearity={0.18}
        zoomSnap={0.25}
        zoomDelta={0.5}
        wheelPxPerZoomLevel={160}
        wheelDebounceTime={35}
        zoomAnimationThreshold={4}
        fadeAnimation={false}
        className={isMapZooming ? "leaflet-stage leaflet-stage--zooming" : "leaflet-stage"}
        scrollWheelZoom
      >
        <MapViewportTracker onChange={setRenderBounds} onZoomingChange={setIsMapZooming} />
        <MapClickPlacement />
        <MovingObjectsLayer
          threats={visibleThreats}
          shots={visibleShots}
          impacts={visibleImpactMarkers}
          elapsedMs={game.elapsedMs}
          mapMode={mapMode}
          reducedQuality={reducedQuality}
        />
        <TileLayer
          url={darkMapTiles.url}
          attribution={darkMapTiles.attribution}
          className={darkMapTiles.className}
          keepBuffer={4}
          updateWhenIdle={false}
          updateWhenZooming
        />
        {visibleOccupiedZonePolygons.map((polygon, index) => (
          <Polygon
            key={`occupied-${index}`}
            positions={polygon.positions}
            pathOptions={occupiedZoneStyle}
          />
        ))}
        {placementKind && placementKind !== "boat" ? visibleCities.map((city) => (
          <Circle
            key={`city-exclusion-${city.id}`}
            center={[city.coordinates.lat, city.coordinates.lng]}
            radius={CITY_PLACEMENT_EXCLUSION_KM * 1000}
            renderer={radiusOverlayRenderer}
            pathOptions={{
              color: "#ff8b6e",
              fillColor: "#ff4f4f",
              fillOpacity: reducedQuality ? 0.035 : 0.055,
              opacity: reducedQuality ? 0.42 : 0.58,
              weight: 1,
              dashArray: "4 5",
              className: "city-exclusion-ring",
            }}
          />
        )) : null}
        {visibleLaunchSectors.map((sector) => (
          <Marker key={sector.id} position={[sector.coordinates.lat, sector.coordinates.lng]} icon={makeLaunchIcon(sector)}>
            <Tooltip direction="left" offset={[-8, 0]}>
              {sector.name} - {sector.state || "idle"}
            </Tooltip>
          </Marker>
        ))}
        {visibleCarriers.map((carrier) => (
          <Marker key={carrier.id} position={[carrier.position.lat, carrier.position.lng]} icon={makeCarrierIcon(carrier)}>
            <Tooltip direction="top" offset={[0, -10]}>
              {carrier.kind === "tu95" ? "Aviation carrier marker" : "Naval carrier marker"} - fictional UI entity
            </Tooltip>
          </Marker>
        ))}
        {visibleCoverageBatteries.map((battery) => {
          const unit = getUnitDefinition(battery.kind);
          const selected = battery.id === selectedBatteryId;
          const coverage = coverageTone(unit, selected);
          return (
            <Fragment key={`coverage-wrap-${battery.id}`}>
              <Circle
                key={`coverage-${battery.id}`}
                center={[battery.position.lat, battery.position.lng]}
                radius={battery.coverageRadius * 72000}
                renderer={radiusOverlayRenderer}
                pathOptions={{
                  color: coverage.color,
                  fillColor: coverage.fill,
                  fillOpacity: reducedQuality ? coverage.fillOpacity * 0.62 : coverage.fillOpacity,
                  opacity: reducedQuality ? coverage.opacity * 0.72 : coverage.opacity,
                  weight: reducedQuality ? Math.max(1, coverage.weight - 0.35) : coverage.weight,
                  className: unit.engagementMode === "detect" ? "coverage-ring coverage-ring--radar" : "coverage-ring",
                }}
              />
            </Fragment>
          );
        })}
        {visibleRoutes.map((route) => (
          <Polyline
            key={route.id}
            positions={[[route.from.lat, route.from.lng], [route.to.lat, route.to.lng]]}
            pathOptions={{ color: routeColor(route), weight: reducedQuality ? 1.35 : 2, opacity: reducedQuality ? 0.42 : 0.62, dashArray: route.status === "well-supplied" ? "3 7" : "8 5" }}
          >
            <Tooltip direction="top" offset={[0, -8]}>
              {route.label} - delay {route.delayDays} cycle(s)
            </Tooltip>
          </Polyline>
        ))}
        {cityMarkers.map(({ city, icon }) => (
          <Marker
            key={city.id}
            position={[city.coordinates.lat, city.coordinates.lng]}
            icon={icon}
          >
            <Tooltip direction="top" offset={[0, -16]}>
              {city.name} - city services {Math.round(city.infrastructure)}%
            </Tooltip>
          </Marker>
        ))}
        {visibleBatteries.map((battery) => (
          <Marker
            key={battery.id}
            position={[battery.position.lat, battery.position.lng]}
            icon={makeBatteryIcon(battery, battery.id === selectedBatteryId)}
            eventHandlers={{ click: () => setSelectedBattery(battery.id) }}
          >
            <Tooltip direction="top" offset={[0, -14]}>
              {(() => {
                const unit = getUnitDefinition(battery.kind);
                const ammo = battery.currentAmmo === "infinite" ? "∞" : `${battery.currentAmmo}/${unit.ammoCapacity}`;
                const reload = battery.reloadRemainingMs > 0 ? ` - reload ${Math.ceil(battery.reloadRemainingMs / 1000)}s` : "";
                return `${unit.shortName} - ${unit.primaryRangeKm}/${unit.outerRangeKm} км - БК ${ammo} - ${Math.round(battery.readiness)}% - ${battery.status}${reload}`;
              })()}
            </Tooltip>
          </Marker>
        ))}
      </MapContainer>
      <PerformanceOverlay stats={performanceStats} counts={renderCounts} />
    </>
  );
}
