import L from "leaflet";
import { Circle, Marker, Polygon, Polyline, TileLayer, Tooltip, MapContainer, useMapEvents } from "react-leaflet";
import { Fragment, useMemo } from "react";
import { carrierSprites, launchSprites, markerSprites, threatSprites, unitSprites } from "../assets/sprites/spriteCatalog";
import { controlOverlay } from "../data/controlZones";
import { getUnitDefinition } from "../data/units";
import { useGameStore } from "../store/useGameStore";
import type {
  City,
  CarrierTrack,
  DefenseBattery,
  ImpactMarker,
  InfrastructureKind,
  InfrastructureNode,
  InterceptorShot,
  LaunchSector,
  LiveThreat,
  SupplyNode,
  SupplyRoute,
} from "../types/game";

const mapCenter: [number, number] = [48.7, 31.4];

const nodeGlyph: Record<InfrastructureKind, string> = {
  energy: "E",
  logistics: "L",
  industry: "I",
  communications: "C",
};

function threatPosition(threat: LiveThreat) {
  return {
    lat: threat.origin.lat + (threat.target.lat - threat.origin.lat) * threat.progress,
    lng: threat.origin.lng + (threat.target.lng - threat.origin.lng) * threat.progress,
  };
}

function shotPosition(shot: InterceptorShot) {
  return {
    lat: shot.from.lat + (shot.to.lat - shot.from.lat) * shot.progress,
    lng: shot.from.lng + (shot.to.lng - shot.from.lng) * shot.progress,
  };
}

function toPositions(points: Array<{ lat: number; lng: number }>): [number, number][] {
  return points.map((point) => [point.lat, point.lng]);
}

function makeCityIcon(city: City, selected: boolean) {
  const damageClass = city.damage > 55 ? "danger" : city.damage > 25 ? "warning" : "stable";
  const alert = city.alertState || "calm";
  return L.divIcon({
    className: "",
    html: `<span class="city-marker-label city-marker-label--${alert}"><span class="map-marker map-marker--city map-marker--${damageClass} map-marker--city-${alert} ${selected ? "map-marker--selected" : ""}">${city.name.slice(0, 1)}</span><b>${city.name}</b></span>`,
    iconSize: [118, 34],
    iconAnchor: [17, 17],
  });
}

function makeNodeIcon(node: InfrastructureNode) {
  const tone = node.integrity < 35 ? "danger" : node.integrity < 65 ? "warning" : "stable";
  return L.divIcon({
    className: "",
    html: `<span class="map-marker map-marker--node map-marker--${tone}">${nodeGlyph[node.kind]}</span>`,
    iconSize: [26, 26],
    iconAnchor: [13, 13],
  });
}

function imageMarkerHtml(src: string, className: string) {
  return `<span class="map-marker map-marker--image ${className}"><img src="${src}" alt="" draggable="false" /></span>`;
}

function threatTone(threat: LiveThreat) {
  if (threat.kind === "decoy") return "decoy";
  if (threat.status === "engaged") return "confirmed";
  if (threat.detected || threat.confidence >= 55) return "detected";
  return "uncertain";
}

function threatLabel(threat: LiveThreat) {
  const tone = threatTone(threat);
  const label = tone === "confirmed" ? "confirmed" : tone === "detected" ? "detected" : tone === "decoy" ? "possible decoy" : "uncertain";
  return `<span class="threat-confidence threat-confidence--${tone}">${label} ${Math.round(threat.confidence)}%</span>`;
}

function threatRouteColor(tone: ReturnType<typeof threatTone>) {
  if (tone === "confirmed") return "#ff3535";
  if (tone === "detected") return "#ffd24a";
  if (tone === "decoy") return "#b997ff";
  return "#35d8ff";
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
  return L.divIcon({
    className: "",
    html: imageMarkerHtml(unitSprites[battery.kind], `map-marker--battery map-marker--unit-${battery.status} ${selected ? "map-marker--selected" : ""}`),
    iconSize: [22, 22],
    iconAnchor: [11, 11],
  });
}

function makeThreatIcon(threat: LiveThreat) {
  const tone = threatTone(threat);
  const label = threat.confidence >= 70 ? threatLabel(threat) : "";
  const targetHeading = threat.headingDeg - 90;
  return L.divIcon({
    className: "",
    html: `<span class="threat-marker-wrap threat-marker-wrap--compact" style="--target-heading:${targetHeading}deg"><span class="target-sprite target-sprite--${tone}"><img src="${threatSprites[threat.kind]}" alt="" draggable="false" /></span>${label}</span>`,
    iconSize: [34, 24],
    iconAnchor: [8, 8],
  });
}

function makeShotIcon() {
  return L.divIcon({
    className: "",
    html: imageMarkerHtml(markerSprites.interceptorShot, "map-marker--shot"),
    iconSize: [14, 14],
    iconAnchor: [7, 7],
  });
}

function makeImpactIcon(marker: ImpactMarker) {
  return L.divIcon({
    className: "",
    html: imageMarkerHtml(marker.tone === "impact" ? markerSprites.impactEvent : markerSprites.interceptedThreat, `map-marker--${marker.tone}`),
    iconSize: [20, 20],
    iconAnchor: [10, 10],
  });
}

function makeLaunchIcon(sector: LaunchSector) {
  const category = sector.category || "drone";
  return L.divIcon({
    className: "",
    html: imageMarkerHtml(launchSprites[category], `map-marker--launch map-marker--launch-${sector.state || "idle"}`),
    iconSize: [18, 18],
    iconAnchor: [9, 9],
  });
}

function makeCarrierIcon(carrier: CarrierTrack) {
  return L.divIcon({
    className: "",
    html: imageMarkerHtml(carrierSprites[carrier.kind], "map-marker--carrier"),
    iconSize: [20, 20],
    iconAnchor: [10, 10],
  });
}

function makeSupplyNodeIcon(node: SupplyNode) {
  return L.divIcon({
    className: "",
    html: imageMarkerHtml(markerSprites.detectedTrack, `map-marker--supply map-marker--supply-${node.source}`),
    iconSize: [34, 34],
    iconAnchor: [17, 17],
  });
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

export function TacticalMap() {
  const game = useGameStore((state) => state.game);
  const selectedCityId = useGameStore((state) => state.selectedCityId);
  const selectedBatteryId = useGameStore((state) => state.selectedBatteryId);
  const mapMode = useGameStore((state) => state.mapMode);
  const setSelectedCity = useGameStore((state) => state.setSelectedCity);
  const setSelectedBattery = useGameStore((state) => state.setSelectedBattery);

  const cityMarkers = useMemo(
    () => game.cities.map((city) => ({
      city,
      icon: makeCityIcon(city, city.id === selectedCityId),
    })),
    [game.cities, selectedCityId],
  );
  const nodeMarkers = useMemo(
    () => game.infrastructure.map((node) => ({ node, icon: makeNodeIcon(node) })),
    [game.infrastructure],
  );

  return (
    <MapContainer
      center={mapCenter}
      zoom={6}
      minZoom={5}
      maxZoom={8}
      zoomControl={false}
      attributionControl={false}
      className="leaflet-stage"
      scrollWheelZoom
    >
      <MapClickPlacement />
      <TileLayer
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        attribution="&copy; OpenStreetMap contributors"
      />
      <Polygon
        positions={toPositions(controlOverlay.controlledUkrainePolygon)}
        pathOptions={{ color: "#5edc8b", fillColor: "#5edc8b", fillOpacity: 0.035, opacity: 0.22, weight: 1 }}
      />
      {controlOverlay.temporarilyOccupiedPolygons.map((polygon, index) => (
        <Polygon
          key={`occupied-${index}`}
          positions={toPositions(polygon)}
          pathOptions={{ color: "#ff6e6e", fillColor: "#ff6e6e", fillOpacity: 0.08, opacity: 0.32, weight: 1, dashArray: "6 6" }}
        />
      ))}
      <Polyline
        positions={toPositions(controlOverlay.frontline)}
        pathOptions={{ color: "#ff6e6e", weight: 2, opacity: 0.62, dashArray: "8 5" }}
      />
      <Polyline
        positions={toPositions(controlOverlay.hostileBorder)}
        pathOptions={{ color: "#f2c865", weight: 1, opacity: 0.44, dashArray: "4 7" }}
      />
      {game.launchSectors.map((sector) => (
        <Marker key={sector.id} position={[sector.coordinates.lat, sector.coordinates.lng]} icon={makeLaunchIcon(sector)}>
          <Tooltip direction="left" offset={[-8, 0]}>
            {sector.name} - {sector.state || "idle"}
          </Tooltip>
        </Marker>
      ))}
      {game.carriers.map((carrier) => (
        <Marker key={carrier.id} position={[carrier.position.lat, carrier.position.lng]} icon={makeCarrierIcon(carrier)}>
          <Tooltip direction="top" offset={[0, -10]}>
            {carrier.kind === "tu95" ? "Aviation carrier marker" : "Naval carrier marker"} - fictional UI entity
          </Tooltip>
        </Marker>
      ))}
      {game.liveThreats.filter((threat) => threat.revealed && threat.confidence >= 58).map((threat) => {
        const current = threatPosition(threat);
        const tone = threatTone(threat);
        return (
          <Polyline
            key={`route-${threat.id}`}
            positions={[[current.lat, current.lng], [threat.target.lat, threat.target.lng]]}
            pathOptions={{
              color: threatRouteColor(tone),
              weight: mapMode === "threats" ? 3 : 2,
              opacity: mapMode === "coverage" ? 0.44 : 0.72,
              dashArray: tone === "confirmed" ? "10 4" : "6 6",
            }}
          />
        );
      })}
      {mapMode !== "threats" ? game.batteries.map((battery) => {
        const unit = getUnitDefinition(battery.kind);
        const selected = battery.id === selectedBatteryId;
        const coverage = coverageTone(unit, selected);
        return (
          <Fragment key={`coverage-wrap-${battery.id}`}>
            <Circle
              key={`coverage-${battery.id}`}
              center={[battery.position.lat, battery.position.lng]}
              radius={battery.coverageRadius * 72000}
              pathOptions={{
                color: coverage.color,
                fillColor: coverage.fill,
                fillOpacity: coverage.fillOpacity,
                opacity: coverage.opacity,
                weight: coverage.weight,
                className: unit.engagementMode === "detect" ? "coverage-ring coverage-ring--radar" : "coverage-ring",
              }}
            />
          </Fragment>
        );
      }) : null}
      {mapMode === "logistics" ? game.logistics.routes.map((route) => (
        <Polyline
          key={route.id}
          positions={[[route.from.lat, route.from.lng], [route.to.lat, route.to.lng]]}
          pathOptions={{ color: routeColor(route), weight: 2, opacity: 0.62, dashArray: route.status === "well-supplied" ? "3 7" : "8 5" }}
        >
          <Tooltip direction="top" offset={[0, -8]}>
            {route.label} - delay {route.delayDays} cycle(s)
          </Tooltip>
        </Polyline>
      )) : null}
      {mapMode === "logistics" ? game.logistics.nodes.map((node) => (
        <Marker key={`supply-${node.id}`} position={[node.position.lat, node.position.lng]} icon={makeSupplyNodeIcon(node)}>
          <Tooltip direction="top" offset={[0, -14]}>
            {node.name} - supply strength {Math.round(node.strength)}%
          </Tooltip>
        </Marker>
      )) : null}
      {nodeMarkers.map(({ node, icon }) => (
        <Marker
          key={node.id}
          position={[node.coordinates.lat, node.coordinates.lng]}
          icon={icon}
          eventHandlers={{ click: () => setSelectedCity(node.cityId) }}
        >
          <Tooltip direction="top" offset={[0, -12]}>
            {node.name} - {Math.round(node.integrity)}%
          </Tooltip>
        </Marker>
      ))}
      {cityMarkers.map(({ city, icon }) => (
        <Marker
          key={city.id}
          position={[city.coordinates.lat, city.coordinates.lng]}
          icon={icon}
          eventHandlers={{ click: () => setSelectedCity(city.id) }}
        >
          <Tooltip direction="top" offset={[0, -16]}>
            {city.name} - infrastructure {Math.round(city.infrastructure)}%
          </Tooltip>
        </Marker>
      ))}
      {game.batteries.map((battery) => (
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
      {game.liveThreats.filter((threat) => threat.revealed).map((threat) => {
        const current = threatPosition(threat);
        return (
          <Marker key={threat.id} position={[current.lat, current.lng]} icon={makeThreatIcon(threat)}>
            <Tooltip direction="top" offset={[0, -14]}>
              {threat.kind} - {threat.status} - track quality {Math.round(threat.trackQuality)}%
            </Tooltip>
          </Marker>
        );
      })}
      {game.interceptorShots.map((shot) => {
        const current = shotPosition(shot);
        return (
          <Fragment key={shot.id}>
            <Polyline
              positions={[[shot.from.lat, shot.from.lng], [current.lat, current.lng]]}
              pathOptions={{
                color: shot.style === "gun" ? "#ffd466" : shot.style === "drone" ? "#7ee7ff" : shot.style === "ew" ? "#b58cff" : "#ffef9a",
                weight: shot.style === "gun" ? 2 : 1,
                opacity: 0.74,
                dashArray: shot.style === "missile" ? "8 5" : shot.style === "gun" ? "2 7" : "4 5",
              }}
            />
            <Marker position={[current.lat, current.lng]} icon={makeShotIcon()} />
          </Fragment>
        );
      })}
      {game.impactMarkers.map((marker) => (
        <Marker key={marker.id} position={[marker.position.lat, marker.position.lng]} icon={makeImpactIcon(marker)} />
      ))}
    </MapContainer>
  );
}
