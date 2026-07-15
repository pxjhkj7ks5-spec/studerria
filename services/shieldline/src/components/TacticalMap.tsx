import L from "leaflet";
import { Circle, CircleMarker, Marker, Polygon, Polyline, Popup, TileLayer, Tooltip, MapContainer, useMap, useMapEvents } from "react-leaflet";
import { Fragment, memo, useEffect, useMemo, useRef, useState } from "react";
import { carrierSprites, launchSprites, launcherVariantSprites, threatSprites, unitSprites } from "../assets/sprites/spriteCatalog";
import { getControlOverlay } from "../data/controlZones";
import { darkMapTiles } from "../data/mapTiles";
import { formatThreatAltitude, formatThreatSpeed, threatDisplayName } from "../data/threatFlightProfiles";
import { getUnitDefinition } from "../data/units";
import { CITY_PLACEMENT_EXCLUSION_KM } from "../game/placementRules";
import { batteryCoverageState } from "../game/coverageVisuals";
import { SHOW_LAUNCH_DEBUG, launchSectorCategory, launchSectorCenter } from "../game/launchSystem.mjs";
import { launcherVariantForSector } from "../game/launcherVariants";
import { mapZoomInputProfile, wheelZoomDelta, type MapZoomInputProfile } from "../game/mapZoom";
import { advanceVisualThreatProgress, classifyThreatRoute, predictedRouteEndpoint, type ThreatRouteVisual } from "../game/threatRouteVisuals";
import { resolveReducedQuality } from "../platform/displayPreferences";
import { useGameStore } from "../store/useGameStore";
import type {
  City,
  CarrierTrack,
  DefenseBattery,
  EngagementEvent,
  ImpactMarker,
  LaunchSector,
  LiveThreat,
  SupplyRoute,
} from "../types/game";

const mapCenter: [number, number] = [48.7, 31.4];
const CHUNK_SIZE_DEG = 2;
const VIEWPORT_PAD_RATIO = 0.42;
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
const engagementIconCache = new Map<string, L.DivIcon>();
const impactIconCache = new Map<string, L.DivIcon>();
const launchSectorIconCache = new Map<string, L.DivIcon>();
const carrierIconCache = new Map<string, L.DivIcon>();
const threatIconCache = new Map<string, L.DivIcon>();

function threatPosition(threat: LiveThreat) {
  return {
    lat: threat.origin.lat + (threat.target.lat - threat.origin.lat) * threat.progress,
    lng: threat.origin.lng + (threat.target.lng - threat.origin.lng) * threat.progress,
  };
}

function threatPositionAtProgress(threat: LiveThreat, progress: number) {
  return {
    lat: threat.origin.lat + (threat.target.lat - threat.origin.lat) * progress,
    lng: threat.origin.lng + (threat.target.lng - threat.origin.lng) * progress,
  };
}

function engagementPosition(event: EngagementEvent, progress = event.progress) {
  return {
    lat: event.startPosition.lat + (event.targetPredictedPosition.lat - event.startPosition.lat) * progress,
    lng: event.startPosition.lng + (event.targetPredictedPosition.lng - event.startPosition.lng) * progress,
  };
}

function interpolatedEngagementProgress(event: EngagementEvent, elapsedSinceSyncMs: number) {
  return Math.min(1, event.progress + elapsedSinceSyncMs / event.durationMs);
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
  if (threat.status === "engaged" || threat.confidence >= 58) return "confirmed";
  return "uncertain";
}

type TargetLabelStatus = "radar" | "confirmed" | "intercepted" | "hit";

function targetLabelStatus(threat: LiveThreat): TargetLabelStatus {
  if (threat.status === "impact") return "hit";
  if (threat.status === "intercepted") return "intercepted";
  if (threat.status === "engaged" || threat.confidence >= 58) return "confirmed";
  return "radar";
}

function targetLabelStatusText(status: TargetLabelStatus) {
  if (status === "confirmed") return "CONFIRMED";
  if (status === "intercepted") return "INTERCEPTED";
  if (status === "hit") return "HIT";
  return "RADAR";
}

function threatRouteColor(tone: ReturnType<typeof threatTone>) {
  if (tone === "confirmed") return "#ff625a";
  if (tone === "decoy") return "#b79af4";
  return "#d8d3c7";
}

function coverageTone(unit: ReturnType<typeof getUnitDefinition>, battery: DefenseBattery) {
  const state = batteryCoverageState(battery, unit.ammoCapacity);
  if (state === "maintenance") {
    return { color: "#ffad42", fill: "#ff8f1f", fillOpacity: 0.1, opacity: 0.78, weight: 2 };
  }
  if (unit.engagementMode === "detect") {
    return { color: "#63c7d4", fill: "#4fb5c4", fillOpacity: 0.045, opacity: 0.78, weight: 1.45 };
  }
  if (state === "empty") {
    return { color: "#ff625a", fill: "#ff3f38", fillOpacity: 0.13, opacity: 0.88, weight: 2.1 };
  }
  return { color: "#f6c547", fill: "#f6c547", fillOpacity: 0.06, opacity: 0.56, weight: 1.35 };
}

interface CoverageCircleProps {
  lat: number;
  lng: number;
  radius: number;
  color: string;
  fillColor: string;
  fillOpacity: number;
  opacity: number;
  weight: number;
  radar: boolean;
}

const CoverageCircle = memo(function CoverageCircle({ lat, lng, radius, color, fillColor, fillOpacity, opacity, weight, radar }: CoverageCircleProps) {
  const center = useMemo<[number, number]>(() => [lat, lng], [lat, lng]);
  const pathOptions = useMemo(() => ({
    color,
    fillColor,
    fillOpacity,
    opacity,
    weight,
    className: radar ? "coverage-ring coverage-ring--radar" : "coverage-ring",
  }), [color, fillColor, fillOpacity, opacity, radar, weight]);

  return <Circle center={center} radius={radius} pathOptions={pathOptions} />;
});

function makeBatteryIcon(battery: DefenseBattery) {
  const key = `${battery.kind}:${battery.status}`;
  const cached = batteryIconCache.get(key);
  if (cached) return cached;
  const icon = L.divIcon({
    className: "",
    html: imageMarkerHtml(unitSprites[battery.kind], "map-marker--battery"),
    iconSize: [22, 22],
    iconAnchor: [11, 11],
  });
  batteryIconCache.set(key, icon);
  return icon;
}

function threatMarkerIconKey(threat: LiveThreat) {
  const tone = threatTone(threat);
  const labelStatus = targetLabelStatus(threat);
  const targetHeading = Math.round(threat.headingDeg - 90);
  return `${threat.kind}:${tone}:${labelStatus}:${targetHeading}:${threat.speedKph}:${threat.altitudeM}`;
}

function makeThreatIcon(threat: LiveThreat) {
  const tone = threatTone(threat);
  const labelStatus = targetLabelStatus(threat);
  const targetHeading = Math.round(threat.headingDeg - 90);
  const course = String(Math.round(threat.headingDeg) % 360).padStart(3, "0");
  const key = threatMarkerIconKey(threat);
  const cached = threatIconCache.get(key);
  if (cached) return cached;
  const icon = L.divIcon({
    className: "",
    html: `<span class="threat-marker-wrap threat-marker-wrap--compact" style="--target-heading:${targetHeading}deg"><span class="target-sprite target-sprite--${tone}"><img src="${threatSprites[threat.kind]}" alt="" draggable="false" /></span><span class="target-label target-label--${labelStatus}" aria-hidden="true"><span class="target-label__head"><b>${threatDisplayName(threat.kind)}</b><i>${targetLabelStatusText(labelStatus)}</i></span><span class="target-label__metrics"><span>${formatThreatSpeed(threat.speedKph)}</span><span>${formatThreatAltitude(threat.altitudeM)}</span></span><span class="target-label__course">КУРС ${course}°</span></span></span>`,
    iconSize: [32, 32],
    iconAnchor: [16, 16],
  });
  threatIconCache.set(key, icon);
  return icon;
}

type EngagementVisualPhase = "lock" | "travel" | "success" | "miss" | "detected";

function makeEngagementProjectileIcon(style: EngagementEvent["style"], simplified: boolean) {
  const key = `projectile:${style}:${simplified ? "simple" : "full"}`;
  const cached = engagementIconCache.get(key);
  if (cached) return cached;
  const icon = L.divIcon({
    className: "",
    html: `<span class="engagement-projectile engagement-projectile--${style} ${simplified ? "engagement-projectile--simple" : ""}"><i></i></span>`,
    iconSize: [18, 18],
    iconAnchor: [9, 9],
  });
  engagementIconCache.set(key, icon);
  return icon;
}

function makeEngagementEffectIcon(style: EngagementEvent["style"], phase: EngagementVisualPhase, simplified: boolean) {
  const key = `effect:${style}:${phase}:${simplified ? "simple" : "full"}`;
  const cached = engagementIconCache.get(key);
  if (cached) return cached;
  const label = phase === "success" ? "INTERCEPTED" : phase === "miss" ? "MISS" : phase === "detected" ? "TRACK" : phase === "lock" ? "LOCK" : "ENGAGING";
  const icon = L.divIcon({
    className: "",
    html: `<span class="engagement-effect engagement-effect--${style} engagement-effect--${phase} ${simplified ? "engagement-effect--simple" : ""}"><i></i><b>${label}</b></span>`,
    iconSize: [86, 44],
    iconAnchor: [43, 22],
  });
  engagementIconCache.set(key, icon);
  return icon;
}

function makeImpactIcon(marker: ImpactMarker) {
  const key = marker.tone;
  const cached = impactIconCache.get(key);
  if (cached) return cached;
  const label = marker.tone === "impact" ? "Влучання" : "Збито";
  const icon = L.divIcon({
    className: "",
    html: `<span class="combat-result-marker combat-result-marker--${marker.tone}" aria-label="${label}"><i class="combat-result-marker__ring"></i><i class="combat-result-marker__axis"></i><i class="combat-result-marker__core"></i></span>`,
    iconSize: [52, 52],
    iconAnchor: [26, 26],
  });
  impactIconCache.set(key, icon);
  return icon;
}

function makeLaunchSectorIcon(sector: LaunchSector) {
  const category = launchSectorCategory(sector);
  const variant = launcherVariantForSector(sector);
  const state = sector.state || "idle";
  const exactPoint = sector.id.startsWith("campaign-launch-");
  const key = `${variant}:${state}:${exactPoint ? "point" : "sector"}`;
  const cached = launchSectorIconCache.get(key);
  if (cached) return cached;
  const icon = L.divIcon({
    className: "",
    html: `<span class="launch-sector-marker ${exactPoint ? "launch-point-marker" : ""} launch-sector-marker--${state}">${imageMarkerHtml(launcherVariantSprites[variant] || launchSprites[category], "map-marker--launch-sector")}</span>`,
    iconSize: [46, 46],
    iconAnchor: [23, 23],
  });
  launchSectorIconCache.set(key, icon);
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
  const map = useMap();
  const placementKind = useGameStore((state) => state.placementKind);
  const placeSelectedBattery = useGameStore((state) => state.placeSelectedBattery);

  useEffect(() => {
    if (!placementKind) return undefined;
    const container = map.getContainer();
    let pointerStart: { id: number; x: number; y: number } | null = null;
    const isMapUi = (target: EventTarget | null) => target instanceof Element && Boolean(target.closest("button, a, .leaflet-control, .leaflet-popup"));
    const handlePointerDown = (event: PointerEvent) => {
      if (event.button !== 0 || isMapUi(event.target)) return;
      pointerStart = { id: event.pointerId, x: event.clientX, y: event.clientY };
    };
    const handlePointerUp = (event: PointerEvent) => {
      const start = pointerStart;
      pointerStart = null;
      if (!start || start.id !== event.pointerId || event.button !== 0 || isMapUi(event.target)) return;
      if (Math.hypot(event.clientX - start.x, event.clientY - start.y) > 10) return;
      const latlng = map.mouseEventToLatLng(event);
      placeSelectedBattery({ lat: latlng.lat, lng: latlng.lng });
    };
    const cancelPointer = () => { pointerStart = null; };
    container.addEventListener("pointerdown", handlePointerDown, true);
    container.addEventListener("pointerup", handlePointerUp, true);
    container.addEventListener("pointercancel", cancelPointer, true);
    return () => {
      container.removeEventListener("pointerdown", handlePointerDown, true);
      container.removeEventListener("pointerup", handlePointerUp, true);
      container.removeEventListener("pointercancel", cancelPointer, true);
    };
  }, [map, placementKind, placeSelectedBattery]);

  return null;
}

function SmoothWheelZoom({ profile }: { profile: MapZoomInputProfile }) {
  const map = useMap();

  useEffect(() => {
    const container = map.getContainer();
    let targetZoom = map.getZoom();
    let anchor = map.getSize().divideBy(2);
    let frame = 0;

    const renderZoom = () => {
      const currentZoom = map.getZoom();
      const distance = targetZoom - currentZoom;
      if (Math.abs(distance) < 0.001) {
        map.setZoomAround(anchor, targetZoom);
        container.classList.remove("leaflet-stage--smooth-zooming");
        frame = 0;
        map.fire("moveend");
        return;
      }
      map.setZoomAround(anchor, currentZoom + distance * profile.smoothing);
      frame = window.requestAnimationFrame(renderZoom);
    };

    const handleWheel = (event: WheelEvent) => {
      if (!Number.isFinite(event.deltaY)) return;
      event.preventDefault();
      anchor = map.mouseEventToContainerPoint(event);
      if (!frame) targetZoom = map.getZoom();
      const delta = wheelZoomDelta(event.deltaY * (event.ctrlKey ? 2 : 1), event.deltaMode, profile, container.clientHeight);
      targetZoom = Math.max(map.getMinZoom(), Math.min(map.getMaxZoom(), targetZoom + delta));
      if (!frame && Math.abs(targetZoom - map.getZoom()) >= 0.001) {
        container.classList.add("leaflet-stage--smooth-zooming");
        frame = window.requestAnimationFrame(renderZoom);
      }
    };

    container.addEventListener("wheel", handleWheel, { passive: false });
    return () => {
      container.removeEventListener("wheel", handleWheel);
      container.classList.remove("leaflet-stage--smooth-zooming");
      if (frame) window.cancelAnimationFrame(frame);
    };
  }, [map, profile]);

  return null;
}

function DesktopPlacementPreview() {
  const map = useMap();
  const placementKind = useGameStore((state) => state.placementKind);

  useEffect(() => {
    if (!placementKind || !window.matchMedia("(hover: hover) and (pointer: fine) and (min-width: 821px)").matches) return undefined;

    const unit = getUnitDefinition(placementKind);
    const isRadar = unit.engagementMode === "detect";
    const previewColor = isRadar ? "#63c7d4" : "#f6c547";
    const previewFill = isRadar ? "#4fb5c4" : "#f6c547";
    const initial = map.getCenter();
    const group = L.layerGroup();
    const outerCircle = L.circle(initial, {
      radius: unit.outerRangeKm * 1000,
      color: previewColor,
      fillColor: previewFill,
      fillOpacity: isRadar ? 0.045 : 0.035,
      opacity: isRadar ? 0.78 : 0.56,
      weight: isRadar ? 1.45 : 1.4,
      dashArray: isRadar ? undefined : "7 7",
      interactive: false,
      className: `placement-preview-ring placement-preview-ring--outer ${isRadar ? "placement-preview-ring--radar" : ""}`,
    }).addTo(group);
    const primaryCircle = isRadar ? null : L.circle(initial, {
      radius: unit.primaryRangeKm * 1000,
      color: "#ffd76a",
      fillColor: "#f6c547",
      fillOpacity: 0.07,
      opacity: 0.92,
      weight: 1.8,
      interactive: false,
      className: "placement-preview-ring placement-preview-ring--primary",
    }).addTo(group);
    const ghost = L.marker(initial, {
      interactive: false,
      keyboard: false,
      zIndexOffset: 900,
      icon: L.divIcon({
        className: "",
        html: `<span class="placement-ghost"><img src="${unitSprites[unit.kind]}" alt="" draggable="false" /></span>`,
        iconSize: [42, 42],
        iconAnchor: [21, 21],
      }),
    }).addTo(group);
    const info = L.marker(initial, {
      interactive: false,
      keyboard: false,
      zIndexOffset: 910,
      icon: L.divIcon({
        className: "",
        html: `<span class="placement-preview-card"><small>${unit.technicalCode}</small><b>${unit.name}</b><span>${unit.costLabel} · ${isRadar ? `${unit.outerRangeKm} км виявлення` : `${unit.primaryRangeKm}/${unit.outerRangeKm} км`}</span>${isRadar ? "" : `<span>БК ${unit.ammoCapacity === "infinite" ? "∞" : unit.ammoCapacity}</span>`}</span>`,
        iconSize: [190, 72],
        iconAnchor: [-18, 82],
      }),
    }).addTo(group);

    let visible = false;
    const showAt = (event: L.LeafletMouseEvent) => {
      outerCircle.setLatLng(event.latlng);
      primaryCircle?.setLatLng(event.latlng);
      ghost.setLatLng(event.latlng);
      info.setLatLng(event.latlng);
      if (!visible) {
        group.addTo(map);
        visible = true;
      }
    };
    const hide = () => {
      if (!visible) return;
      group.removeFrom(map);
      visible = false;
    };

    map.on("mousemove", showAt);
    map.getContainer().addEventListener("pointerleave", hide);
    return () => {
      map.off("mousemove", showAt);
      map.getContainer().removeEventListener("pointerleave", hide);
      group.removeFrom(map);
    };
  }, [map, placementKind]);

  return null;
}

function MapViewportTracker({
  onChange,
}: {
  onChange: (bounds: RenderBounds) => void;
}) {
  const frameRef = useRef(0);
  const lastKeyRef = useRef("");
  const map = useMapEvents({
    moveend() {
      scheduleViewportFrame();
    },
    zoomend() {
      scheduleViewportFrame();
    },
    resize() {
      scheduleViewportFrame();
    },
  });

  function scheduleViewportFrame() {
    if (map.getContainer().classList.contains("leaflet-stage--smooth-zooming")) return;
    window.cancelAnimationFrame(frameRef.current);
    frameRef.current = window.requestAnimationFrame(() => {
      const next = createRenderBounds(map);
      if (next.key === lastKeyRef.current) return;
      lastKeyRef.current = next.key;
      onChange(next);
    });
  }

  useEffect(() => {
    scheduleViewportFrame();
    return () => {
      window.cancelAnimationFrame(frameRef.current);
    };
  }, []);

  return null;
}

function ThreatLabelZoomMode() {
  const map = useMap();

  useEffect(() => {
    const container = map.getContainer();
    const syncDetail = () => {
      const zoom = map.getZoom();
      container.classList.toggle("threat-labels--far", zoom < 6);
      container.classList.toggle("threat-labels--close", zoom >= 8);
    };
    syncDetail();
    map.on("zoom", syncDetail);
    return () => {
      map.off("zoom", syncDetail);
      container.classList.remove("threat-labels--far", "threat-labels--close");
    };
  }, [map]);

  return null;
}

interface PooledEngagementVisual {
  projectile: L.Marker;
  routes: L.Polyline[];
  effect: L.Marker;
  phase: EngagementVisualPhase;
  simplified: boolean;
}

function clampNumber(value: number, minimum: number, maximum: number) {
  return Math.max(minimum, Math.min(maximum, value));
}

function coordinateBetween(from: { lat: number; lng: number }, to: { lat: number; lng: number }, progress: number) {
  return {
    lat: from.lat + (to.lat - from.lat) * progress,
    lng: from.lng + (to.lng - from.lng) * progress,
  };
}

function engagementVisualPhase(event: EngagementEvent, progress: number): EngagementVisualPhase {
  if (event.style === "radar") return progress >= 0.58 ? "detected" : "lock";
  if (progress < 0.16) return "lock";
  if (progress < 0.82) return "travel";
  return event.result === "success" ? "success" : "miss";
}

function updateEngagementVisual(map: L.Map, event: EngagementEvent, pooled: PooledEngagementVisual, progress: number) {
  const phase = engagementVisualPhase(event, progress);
  if (phase !== pooled.phase) {
    pooled.phase = phase;
    pooled.effect.setIcon(makeEngagementEffectIcon(event.style, phase, pooled.simplified));
  }
  pooled.effect.setLatLng([event.targetPredictedPosition.lat, event.targetPredictedPosition.lng]);

  if (event.style === "radar") {
    pooled.projectile.setOpacity(0);
    for (const route of pooled.routes) route.setStyle({ opacity: 0 });
    return;
  }

  const travelProgress = clampNumber((progress - 0.13) / 0.69, 0, 1);
  const activeTravel = phase === "travel";
  pooled.projectile.setOpacity(activeTravel && event.style !== "gun" ? 1 : 0);

  if (event.style === "gun") {
    const targetPoint = map.latLngToLayerPoint([event.targetPredictedPosition.lat, event.targetPredictedPosition.lng]);
    pooled.routes.forEach((route, index) => {
      const center = (pooled.routes.length - 1) / 2;
      const offset = index - center;
      const aimed = map.layerPointToLatLng(targetPoint.add(L.point(offset * 4.5, offset * -2.2 + (index % 2 ? 3 : -2))));
      const tracerProgress = clampNumber((travelProgress - index * 0.055) / 0.72, 0, 1);
      const current = coordinateBetween(event.startPosition, aimed, tracerProgress);
      const tail = coordinateBetween(event.startPosition, aimed, Math.max(0, tracerProgress - 0.16));
      route.setLatLngs([[tail.lat, tail.lng], [current.lat, current.lng]]);
      route.setStyle({ opacity: activeTravel && tracerProgress > 0 && tracerProgress < 1 ? (pooled.simplified ? 0.58 : 0.86) : 0 });
    });
    pooled.projectile.setLatLng([event.targetPredictedPosition.lat, event.targetPredictedPosition.lng]);
    return;
  }

  const current = coordinateBetween(event.startPosition, event.targetPredictedPosition, travelProgress);
  const trailLength = pooled.simplified ? 0.1 : event.style === "missile" ? 0.2 : 0.14;
  const tail = coordinateBetween(event.startPosition, event.targetPredictedPosition, Math.max(0, travelProgress - trailLength));
  pooled.projectile.setLatLng([current.lat, current.lng]);
  const route = pooled.routes[0];
  route.setLatLngs([[tail.lat, tail.lng], [current.lat, current.lng]]);
  route.setStyle({ opacity: activeTravel ? (pooled.simplified ? 0.5 : 0.8) : 0 });
}

interface MovingObjectsLayerProps {
  threats: LiveThreat[];
  engagements: EngagementEvent[];
  impacts: ImpactMarker[];
  elapsedMs: number;
  mapMode: string;
  reducedQuality: boolean;
}

function MovingObjectsLayer({ threats, engagements, impacts, elapsedMs, mapMode, reducedQuality }: MovingObjectsLayerProps) {
  const map = useMap();
  const threatGroupRef = useRef<L.LayerGroup | null>(null);
  const engagementGroupRef = useRef<L.LayerGroup | null>(null);
  const impactGroupRef = useRef<L.LayerGroup | null>(null);
  const threatPoolRef = useRef(new Map<string, { marker: L.Marker; route: L.Polyline | null; routeVisual: ThreatRouteVisual; iconKey: string; visualProgress: number }>());
  const engagementPoolRef = useRef(new Map<string, PooledEngagementVisual>());
  const impactPoolRef = useRef(new Map<string, L.Marker>());
  const latestRef = useRef({ threats, engagements, impacts, elapsedMs, mapMode, reducedQuality });
  const syncAtRef = useRef(0);
  const lastSyncedElapsedMsRef = useRef<number | null>(null);
  const mapMovingRef = useRef(false);
  const frameRef = useRef(0);
  const lastAnimationFrameAtRef = useRef<number | null>(null);

  useEffect(() => {
    const threatGroup = L.layerGroup().addTo(map);
    const engagementGroup = L.layerGroup().addTo(map);
    const impactGroup = L.layerGroup().addTo(map);
    threatGroupRef.current = threatGroup;
    engagementGroupRef.current = engagementGroup;
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

    const animate = (timestamp: number) => {
      const frameDeltaMs = lastAnimationFrameAtRef.current === null ? 0 : timestamp - lastAnimationFrameAtRef.current;
      lastAnimationFrameAtRef.current = timestamp;
      if (!mapMovingRef.current) {
        const elapsedSinceSync = Math.max(0, performance.now() - syncAtRef.current);
        const latest = latestRef.current;
        for (const threat of latest.threats) {
          const pooled = threatPoolRef.current.get(threat.id);
          if (!pooled) continue;
          pooled.visualProgress = advanceVisualThreatProgress(pooled.visualProgress, threat.progress, threat.speed, frameDeltaMs);
          const current = threatPositionAtProgress(threat, pooled.visualProgress);
          pooled.marker.setLatLng([current.lat, current.lng]);
          if (pooled.route) {
            const endpoint = pooled.routeVisual === "predicted" ? predictedRouteEndpoint(current, threat.target) : threat.target;
            pooled.route.setLatLngs([[current.lat, current.lng], [endpoint.lat, endpoint.lng]]);
          }
        }
        for (const event of latest.engagements) {
          const pooled = engagementPoolRef.current.get(event.id);
          if (!pooled) continue;
          updateEngagementVisual(map, event, pooled, interpolatedEngagementProgress(event, elapsedSinceSync));
        }
      }
      frameRef.current = window.requestAnimationFrame(animate);
    };
    frameRef.current = window.requestAnimationFrame(animate);

    return () => {
      window.cancelAnimationFrame(frameRef.current);
      lastAnimationFrameAtRef.current = null;
      map.off("movestart", pauseMapAnimation);
      map.off("zoomstart", pauseMapAnimation);
      map.off("moveend", resumeMapAnimation);
      map.off("zoomend", resumeMapAnimation);
      threatGroup.remove();
      engagementGroup.remove();
      impactGroup.remove();
      threatPoolRef.current.clear();
      engagementPoolRef.current.clear();
      impactPoolRef.current.clear();
      threatGroupRef.current = null;
      engagementGroupRef.current = null;
      impactGroupRef.current = null;
    };
  }, [map]);

  useEffect(() => {
    latestRef.current = { threats, engagements, impacts, elapsedMs, mapMode, reducedQuality };
    if (lastSyncedElapsedMsRef.current !== elapsedMs) {
      lastSyncedElapsedMsRef.current = elapsedMs;
      syncAtRef.current = performance.now();
    }
    const elapsedSinceSync = Math.max(0, performance.now() - syncAtRef.current);
    const threatGroup = threatGroupRef.current;
    const engagementGroup = engagementGroupRef.current;
    const impactGroup = impactGroupRef.current;
    if (!threatGroup || !engagementGroup || !impactGroup) return;

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
      const routeVisual = classifyThreatRoute(threat, reducedQuality);
      let pooled = threatPoolRef.current.get(threat.id);
      const visualProgress = advanceVisualThreatProgress(pooled?.visualProgress ?? threat.progress, threat.progress, threat.speed, 0);
      const current = threatPositionAtProgress(threat, visualProgress);
      const routeEndpoint = routeVisual === "predicted" ? predictedRouteEndpoint(current, threat.target) : threat.target;
      const iconKey = threatMarkerIconKey(threat);
      const previousRouteVisual = pooled?.routeVisual;
      if (!pooled) {
        pooled = {
          marker: L.marker([current.lat, current.lng], { icon: makeThreatIcon(threat), interactive: false }).addTo(threatGroup),
          route: null,
          routeVisual,
          iconKey,
          visualProgress,
        };
        threatPoolRef.current.set(threat.id, pooled);
      } else if (pooled.iconKey !== iconKey) {
        pooled.marker.setIcon(makeThreatIcon(threat));
        pooled.iconKey = iconKey;
      }
      pooled.visualProgress = visualProgress;
      if (pooled.route && previousRouteVisual && previousRouteVisual !== routeVisual) {
        pooled.route.remove();
        pooled.route = null;
      }
      pooled.routeVisual = routeVisual;
      if (routeVisual !== "hidden" && !pooled.route) {
        pooled.route = L.polyline([[current.lat, current.lng], [routeEndpoint.lat, routeEndpoint.lng]], {
          color: routeVisual === "predicted" ? "#d8d3c7" : threatRouteColor(tone),
          weight: routeVisual === "predicted" ? 1.5 : mapMode === "threats" ? 3 : 2,
          opacity: routeVisual === "predicted" ? 0.48 : mapMode === "coverage" ? 0.44 : 0.78,
          dashArray: routeVisual === "predicted" ? "5 7" : undefined,
          interactive: false,
        }).addTo(threatGroup);
      } else if (routeVisual === "hidden" && pooled.route) {
        pooled.route.remove();
        pooled.route = null;
      } else if (pooled.route) {
        pooled.route.setLatLngs([[current.lat, current.lng], [routeEndpoint.lat, routeEndpoint.lng]]);
        pooled.route.setStyle({
          color: routeVisual === "predicted" ? "#d8d3c7" : threatRouteColor(tone),
          weight: routeVisual === "predicted" ? 1.5 : mapMode === "threats" ? 3 : 2,
          opacity: routeVisual === "predicted" ? 0.48 : mapMode === "coverage" ? 0.44 : 0.78,
          dashArray: routeVisual === "predicted" ? "5 7" : undefined,
        });
      }
    }

    const engagementIds = new Set(engagements.map((event) => event.id));
    for (const [id, pooled] of engagementPoolRef.current) {
      if (!engagementIds.has(id)) {
        pooled.projectile.remove();
        pooled.effect.remove();
        pooled.routes.forEach((route) => route.remove());
        engagementPoolRef.current.delete(id);
      }
    }
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const touchLike = window.matchMedia("(pointer: coarse)").matches;
    for (const [engagementIndex, event] of engagements.entries()) {
      let pooled = engagementPoolRef.current.get(event.id);
      const simplified = reducedQuality || touchLike || prefersReducedMotion || engagementIndex >= 10;
      const current = engagementPosition(event);
      const pathOptions = {
        color: event.style === "gun" ? "#ffd466" : event.style === "ew" ? "#b79af4" : event.style === "drone" ? "#f6c547" : "#ffef9a",
        weight: event.style === "gun" ? (simplified ? 1.25 : 1.8) : event.style === "ew" ? 1.4 : 1.2,
        opacity: 0,
        dashArray: event.style === "ew" ? "4 6" : undefined,
        interactive: false,
      };
      if (!pooled) {
        const routeCount = event.style === "gun" ? (simplified ? 3 : 5) : 1;
        const routes = Array.from({ length: routeCount }, () => L.polyline(
          [[event.startPosition.lat, event.startPosition.lng], [current.lat, current.lng]],
          pathOptions,
        ).addTo(engagementGroup));
        const phase = engagementVisualPhase(event, event.progress);
        pooled = {
          projectile: L.marker([current.lat, current.lng], { icon: makeEngagementProjectileIcon(event.style, simplified), interactive: false, keyboard: false, zIndexOffset: 820 }).addTo(engagementGroup),
          routes,
          effect: L.marker([event.targetPredictedPosition.lat, event.targetPredictedPosition.lng], { icon: makeEngagementEffectIcon(event.style, phase, simplified), interactive: false, keyboard: false, zIndexOffset: 830 }).addTo(engagementGroup),
          phase,
          simplified,
        };
        engagementPoolRef.current.set(event.id, pooled);
      }
      updateEngagementVisual(map, event, pooled, interpolatedEngagementProgress(event, elapsedSinceSync));
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
  }, [threats, engagements, impacts, elapsedMs, mapMode, reducedQuality]);

  return null;
}

function usePerformanceStats(renderCounts: RenderCounts): PerformanceStats {
  const [stats, setStats] = useState<PerformanceStats>({ fps: 60, frameMs: 16.7, memoryMb: null, quality: "full" });
  const statsRef = useRef(stats);
  const lowFpsSamplesRef = useRef(0);
  const recoveredFpsSamplesRef = useRef(0);

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
        if (fps < LOW_FPS_THRESHOLD) {
          lowFpsSamplesRef.current += 1;
          recoveredFpsSamplesRef.current = 0;
        } else if (fps > RECOVERED_FPS_THRESHOLD) {
          recoveredFpsSamplesRef.current += 1;
          lowFpsSamplesRef.current = 0;
        } else {
          lowFpsSamplesRef.current = 0;
          recoveredFpsSamplesRef.current = 0;
        }
        const quality = statsRef.current.quality === "full"
          ? lowFpsSamplesRef.current >= 3 ? "reduced" : "full"
          : recoveredFpsSamplesRef.current >= 4 ? "full" : "reduced";
        if (quality !== statsRef.current.quality) {
          lowFpsSamplesRef.current = 0;
          recoveredFpsSamplesRef.current = 0;
        }
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

export function TacticalMap({ forcedReducedQuality = false }: { forcedReducedQuality?: boolean }) {
  const game = useGameStore((state) => state.game);
  const mapMode = useGameStore((state) => state.mapMode);
  const placementKind = useGameStore((state) => state.placementKind);
  const moveBatteryToStorage = useGameStore((state) => state.moveBatteryToStorage);
  const [renderBounds, setRenderBounds] = useState<RenderBounds | null>(null);
  const chunkCacheRef = useRef(new Set<string>());
  const [cachedChunkCount, setCachedChunkCount] = useState(0);
  const liveThreats = game.liveThreats;
  const engagementEvents = game.engagementEvents;
  const impactMarkers = game.impactMarkers;
  const sectorActivity = game.launchSectors;
  const elapsedMs = game.elapsedMs;
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
    () => sectorActivity.filter((sector) => pointInBounds(launchSectorCenter(sector), renderBounds, sector.radiusKm / 85)),
    [sectorActivity, renderBounds],
  );
  const visibleCarriers = useMemo(
    () => SHOW_LAUNCH_DEBUG ? game.carriers.filter((carrier) => pointInBounds(carrier.position, renderBounds)) : [],
    [game.carriers, renderBounds],
  );
  const visibleBatteries = useMemo(
    () => game.batteries.filter((battery) => pointInBounds(battery.position, renderBounds, Math.max(0.15, battery.coverageRadius * 0.15))),
    [game.batteries, renderBounds],
  );
  const visibleCoverageBatteries = useMemo(
    () => mapMode === "threats" ? [] : game.batteries,
    [game.batteries, mapMode],
  );
  const visibleRoutes = useMemo(
    () => mapMode === "logistics" ? game.logistics.routes.filter((route) => lineInBounds(route.from, route.to, renderBounds)) : [],
    [game.logistics.routes, mapMode, renderBounds],
  );
  const visibleThreats = useMemo(
    () => liveThreats.filter((threat) => threat.revealed && lineInBounds(threatPosition(threat), threat.target, renderBounds)),
    [liveThreats, renderBounds],
  );
  const visibleEngagements = useMemo(
    () => engagementEvents
      .filter((event) => lineInBounds(event.startPosition, event.targetPredictedPosition, renderBounds))
      .sort((left, right) => Number(left.style === "radar") - Number(right.style === "radar") || right.startedAtMs - left.startedAtMs)
      .slice(0, 32),
    [engagementEvents, renderBounds],
  );
  const visibleImpactMarkers = useMemo(
    () => impactMarkers.filter((marker) => pointInBounds(marker.position, renderBounds)),
    [impactMarkers, renderBounds],
  );
  const visibleDebugLaunchPoints = useMemo(
    () => SHOW_LAUNCH_DEBUG ? liveThreats.filter((threat) => pointInBounds(threat.origin, renderBounds)) : [],
    [liveThreats, renderBounds],
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
      + game.carriers.length
      + game.batteries.length
      + liveThreats.length
      + engagementEvents.length
      + impactMarkers.length
      + (mapMode === "logistics" ? game.logistics.routes.length : 0);
    const renderedObjects = visibleCities.length
      + visibleLaunchSectors.length
      + visibleCarriers.length
      + visibleBatteries.length
      + visibleThreats.length
      + visibleEngagements.length
      + visibleImpactMarkers.length
      + visibleCoverageBatteries.length
      + visibleRoutes.length
      + visibleOccupiedZonePolygons.length
      + visibleDebugLaunchPoints.length;
    return {
      activeObjects,
      renderedObjects,
      activeChunks: renderBounds?.chunkKeys.size || 0,
      cachedChunks: cachedChunkCount,
    };
  }, [
    cachedChunkCount,
    game.cities.length,
    game.carriers.length,
    game.batteries.length,
    liveThreats.length,
    engagementEvents.length,
    impactMarkers.length,
    game.logistics.routes.length,
    mapMode,
    renderBounds,
    visibleBatteries.length,
    visibleCarriers.length,
    visibleCities.length,
    visibleCoverageBatteries.length,
    visibleImpactMarkers.length,
    visibleLaunchSectors.length,
    visibleDebugLaunchPoints.length,
    visibleOccupiedZonePolygons.length,
    visibleRoutes.length,
    visibleEngagements.length,
    visibleThreats.length,
  ]);
  const performanceStats = usePerformanceStats(renderCounts);
  const reducedQuality = resolveReducedQuality(performanceStats.quality === "reduced", forcedReducedQuality);
  const zoomInput = useMemo(
    () => mapZoomInputProfile(typeof window !== "undefined" && window.matchMedia("(pointer: fine)").matches),
    [],
  );

  return (
    <>
      <MapContainer
        center={mapCenter}
        zoom={6}
        minZoom={5}
        maxZoom={12}
        zoomControl={false}
        attributionControl
        zoomAnimation
        markerZoomAnimation
        inertia
        inertiaDeceleration={2400}
        easeLinearity={0.18}
        zoomSnap={0}
        zoomAnimationThreshold={4}
        fadeAnimation={false}
        className="leaflet-stage"
        scrollWheelZoom={false}
      >
        <SmoothWheelZoom profile={zoomInput} />
        <MapViewportTracker onChange={setRenderBounds} />
        <ThreatLabelZoomMode />
        <MapClickPlacement />
        <DesktopPlacementPreview />
        <MovingObjectsLayer
          threats={visibleThreats}
          engagements={visibleEngagements}
          impacts={visibleImpactMarkers}
          elapsedMs={elapsedMs}
          mapMode={mapMode}
          reducedQuality={reducedQuality}
        />
        <TileLayer
          url={darkMapTiles.url}
          attribution={darkMapTiles.attribution}
          className={darkMapTiles.className}
          keepBuffer={4}
          updateWhenIdle
          updateWhenZooming
        />
        {visibleOccupiedZonePolygons.map((polygon, index) => (
          <Polygon
            key={`occupied-${index}`}
            positions={polygon.positions}
            pathOptions={occupiedZoneStyle}
          />
        ))}
        {placementKind && placementKind !== "boat" ? game.cities.map((city) => (
          <Circle
            key={`city-exclusion-${city.id}`}
            center={[city.coordinates.lat, city.coordinates.lng]}
            radius={CITY_PLACEMENT_EXCLUSION_KM * 1000}
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
        {visibleLaunchSectors.map((sector) => {
          const center = launchSectorCenter(sector);
          return (
            <Fragment key={`launch-sector-${sector.id}`}>
              {SHOW_LAUNCH_DEBUG ? (
                <Circle
                  center={[center.lat, center.lng]}
                  radius={sector.radiusKm * 1000}
                  pathOptions={{ color: "#ff9b72", fillColor: "#ff6f61", fillOpacity: 0.035, opacity: 0.28, weight: 1, dashArray: "5 7", className: "launch-sector-debug-radius" }}
                />
              ) : null}
              <Marker position={[center.lat, center.lng]} icon={makeLaunchSectorIcon(sector)}>
                <Tooltip className="launch-sector-tooltip" direction="auto" offset={[8, 0]}>
                  {sector.name} · {sector.role}
                </Tooltip>
              </Marker>
              {sector.lastLaunchCoordinates ? (
                <Marker
                  position={[sector.lastLaunchCoordinates.lat, sector.lastLaunchCoordinates.lng]}
                  icon={makeLaunchSectorIcon({ ...sector, id: `campaign-launch-${sector.id}`, lat: sector.lastLaunchCoordinates.lat, lng: sector.lastLaunchCoordinates.lng, radiusKm: 1 })}
                >
                  <Tooltip className="launch-sector-tooltip" direction="auto" offset={[8, 0]}>Точна точка пуску · {sector.name}</Tooltip>
                </Marker>
              ) : null}
            </Fragment>
          );
        })}
        {visibleDebugLaunchPoints.map((threat) => (
          <CircleMarker key={`debug-launch-${threat.id}`} center={[threat.origin.lat, threat.origin.lng]} radius={4} pathOptions={{ color: "#fff4d0", fillColor: "#ff5f57", fillOpacity: 0.9, weight: 1, className: "launch-point-debug" }}>
            <Tooltip>{threat.launchSectorName} · exact debug spawn</Tooltip>
          </CircleMarker>
        ))}
        {visibleCarriers.map((carrier) => (
          <Marker key={carrier.id} position={[carrier.position.lat, carrier.position.lng]} icon={makeCarrierIcon(carrier)}>
            <Tooltip direction="top" offset={[0, -10]}>
              {carrier.kind === "tu95" ? "Авіаційний носій" : "Морський носій"} · умовна бойова позначка
            </Tooltip>
          </Marker>
        ))}
        {visibleCoverageBatteries.map((battery) => {
          const unit = getUnitDefinition(battery.kind);
          const coverage = coverageTone(unit, battery);
          return <CoverageCircle
            key={`coverage-${battery.id}`}
            lat={battery.position.lat}
            lng={battery.position.lng}
            radius={unit.outerRangeKm * 1000}
            color={coverage.color}
            fillColor={coverage.fill}
            fillOpacity={reducedQuality ? coverage.fillOpacity * 0.62 : coverage.fillOpacity}
            opacity={reducedQuality ? coverage.opacity * 0.72 : coverage.opacity}
            weight={reducedQuality ? Math.max(1, coverage.weight - 0.35) : coverage.weight}
            radar={unit.engagementMode === "detect"}
          />;
        })}
        {visibleRoutes.map((route) => (
          <Polyline
            key={route.id}
            positions={[[route.from.lat, route.from.lng], [route.to.lat, route.to.lng]]}
            pathOptions={{ color: routeColor(route), weight: reducedQuality ? 1.35 : 2, opacity: reducedQuality ? 0.42 : 0.62, dashArray: route.status === "well-supplied" ? "3 7" : "8 5" }}
          >
            <Tooltip direction="top" offset={[0, -8]}>
              {route.label} · затримка {route.delayDays} цикл.
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
              {city.name} · міські служби {Math.round(city.infrastructure)}%
            </Tooltip>
          </Marker>
        ))}
        {visibleBatteries.map((battery) => (
          <Marker
            key={battery.id}
            position={[battery.position.lat, battery.position.lng]}
            icon={makeBatteryIcon(battery)}
          >
            <Popup className="battery-action-popup" closeButton>
              {(() => {
                const unit = getUnitDefinition(battery.kind);
                const ammo = battery.currentAmmo === "infinite" ? "∞" : `${battery.currentAmmo}/${unit.ammoCapacity}`;
                const reload = battery.reloadRemainingMs > 0 ? `${Math.ceil(battery.reloadRemainingMs / 1000)} с` : "готова";
                return <div className="battery-action-popup__content">
                  <span>Встановлена одиниця</span>
                  <strong>{unit.name}</strong>
                  <small>Зона дії {unit.primaryRangeKm}/{unit.outerRangeKm} км</small>
                  <small>Готовність {Math.round(battery.readiness)}% · {battery.status}</small>
                  <small>БК {ammo} · перезаряджання {reload}</small>
                  <button type="button" onClick={() => moveBatteryToStorage(battery.id)}>Перемістити на склад</button>
                </div>;
              })()}
            </Popup>
          </Marker>
        ))}
      </MapContainer>
      <PerformanceOverlay stats={{ ...performanceStats, quality: reducedQuality ? "reduced" : "full" }} counts={renderCounts} />
    </>
  );
}
