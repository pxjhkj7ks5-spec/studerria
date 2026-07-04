import L from "leaflet";
import { Circle, Marker, Polyline, TileLayer, Tooltip, MapContainer, useMapEvents } from "react-leaflet";
import { useMemo } from "react";
import { markerSprites, threatSprites, unitSprites } from "../assets/sprites/spriteCatalog";
import { useGameStore } from "../store/useGameStore";
import type {
  City,
  DefenseBattery,
  ImpactMarker,
  InfrastructureKind,
  InfrastructureNode,
  InterceptorShot,
  LaunchSector,
  LiveThreat,
  SupplyNode,
  SupplyRoute,
  ThreatKind,
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

function makeCityIcon(city: City, selected: boolean) {
  const damageClass = city.damage > 55 ? "danger" : city.damage > 25 ? "warning" : "stable";
  return L.divIcon({
    className: "",
    html: `<span class="city-marker-label"><span class="map-marker map-marker--city map-marker--${damageClass} ${selected ? "map-marker--selected" : ""}">${city.name.slice(0, 1)}</span><b>${city.name}</b></span>`,
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

function makeBatteryIcon(battery: DefenseBattery, selected: boolean) {
  return L.divIcon({
    className: "",
    html: imageMarkerHtml(unitSprites[battery.kind], `map-marker--battery map-marker--unit-${battery.status} ${selected ? "map-marker--selected" : ""}`),
    iconSize: [38, 38],
    iconAnchor: [19, 19],
  });
}

function makeThreatIcon(threat: LiveThreat) {
  const tone = threatTone(threat);
  return L.divIcon({
    className: "",
    html: `<span class="threat-marker-wrap">${imageMarkerHtml(threatSprites[threat.kind], `map-marker--threat map-marker--threat-${tone} map-marker--threat-${threat.status}`)}${threatLabel(threat)}</span>`,
    iconSize: [104, 52],
    iconAnchor: [17, 17],
  });
}

function makeShotIcon() {
  return L.divIcon({
    className: "",
    html: imageMarkerHtml(markerSprites.interceptorShot, "map-marker--shot"),
    iconSize: [24, 24],
    iconAnchor: [12, 12],
  });
}

function makeImpactIcon(marker: ImpactMarker) {
  return L.divIcon({
    className: "",
    html: imageMarkerHtml(marker.tone === "impact" ? markerSprites.impactEvent : markerSprites.interceptedThreat, `map-marker--${marker.tone}`),
    iconSize: [34, 34],
    iconAnchor: [17, 17],
  });
}

function makeLaunchIcon(sector: LaunchSector) {
  const primary = sector.supports[0] || "drone";
  return L.divIcon({
    className: "",
    html: imageMarkerHtml(threatSprites[primary], "map-marker--launch"),
    iconSize: [30, 30],
    iconAnchor: [15, 15],
  });
}

function makeSupplyNodeIcon(node: SupplyNode) {
  return L.divIcon({
    className: "",
    html: imageMarkerHtml(unitSprites.logistics, `map-marker--supply map-marker--supply-${node.source}`),
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
      {game.launchSectors.map((sector) => (
        <Marker key={sector.id} position={[sector.coordinates.lat, sector.coordinates.lng]} icon={makeLaunchIcon(sector)}>
          <Tooltip direction="left" offset={[-8, 0]}>
            Fictional launch sector - {sector.name}
          </Tooltip>
        </Marker>
      ))}
      {game.liveThreats.map((threat) => {
        const current = threatPosition(threat);
        const tone = threatTone(threat);
        return (
          <Polyline
            key={`route-${threat.id}`}
            positions={[[current.lat, current.lng], [threat.target.lat, threat.target.lng]]}
            pathOptions={{
              color: tone === "confirmed" ? "#ff6e6e" : tone === "detected" ? "#f2c865" : tone === "decoy" ? "#a38cff" : "#55d7ff",
              weight: mapMode === "threats" ? 2 : 1,
              opacity: mapMode === "coverage" ? 0.18 : 0.48,
              dashArray: tone === "confirmed" ? "8 4" : "5 7",
            }}
          />
        );
      })}
      {mapMode !== "threats" ? game.batteries.map((battery) => (
        <Circle
          key={`coverage-${battery.id}`}
          center={[battery.position.lat, battery.position.lng]}
          radius={battery.coverageRadius * 85000}
          pathOptions={{
            color: battery.id === selectedBatteryId ? "#f2c865" : "#55d7ff",
            fillColor: battery.id === selectedBatteryId ? "#f2c865" : "#55d7ff",
            fillOpacity: battery.id === selectedBatteryId ? 0.12 : 0.07,
            opacity: battery.id === selectedBatteryId ? 0.75 : 0.42,
            weight: battery.id === selectedBatteryId ? 2 : 1,
          }}
        />
      )) : null}
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
            Coverage {battery.coverageTier} - readiness {Math.round(battery.readiness)}% - {battery.status}
          </Tooltip>
        </Marker>
      ))}
      {game.liveThreats.map((threat) => {
        const current = threatPosition(threat);
        return (
          <Marker key={threat.id} position={[current.lat, current.lng]} icon={makeThreatIcon(threat)}>
            <Tooltip direction="top" offset={[0, -14]}>
              {threat.detected ? threat.kind : "unknown track"} - {threat.status} from fictional sector
            </Tooltip>
          </Marker>
        );
      })}
      {game.interceptorShots.map((shot) => {
        const current = shotPosition(shot);
        return <Marker key={shot.id} position={[current.lat, current.lng]} icon={makeShotIcon()} />;
      })}
      {game.impactMarkers.map((marker) => (
        <Marker key={marker.id} position={[marker.position.lat, marker.position.lng]} icon={makeImpactIcon(marker)} />
      ))}
    </MapContainer>
  );
}
