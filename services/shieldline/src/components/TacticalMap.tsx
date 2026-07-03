import L from "leaflet";
import { Circle, Marker, Polyline, TileLayer, Tooltip, MapContainer, useMapEvents } from "react-leaflet";
import { useMemo } from "react";
import { useGameStore } from "../store/useGameStore";
import type {
  City,
  DefenseBattery,
  ImpactMarker,
  InfrastructureKind,
  InfrastructureNode,
  InterceptorShot,
  LiveThreat,
  ThreatKind,
  UnitKind,
} from "../types/game";

const mapCenter: [number, number] = [48.7, 31.4];

const nodeGlyph: Record<InfrastructureKind, string> = {
  energy: "E",
  logistics: "L",
  industry: "I",
  communications: "C",
};

const batteryGlyph: Record<UnitKind, string> = {
  radar: "R",
  mobile: "M",
  short: "S",
  medium: "X",
  repair: "W",
  logistics: "L",
  intel: "I",
  decoy: "D",
};

const threatGlyph: Record<ThreatKind, string> = {
  drone: "D",
  missile: "M",
  decoy: "?",
  combined: "C",
  saturation: "S",
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

function makeBatteryIcon(battery: DefenseBattery, selected: boolean) {
  return L.divIcon({
    className: "",
    html: `<span class="map-marker map-marker--battery ${selected ? "map-marker--selected" : ""}">${batteryGlyph[battery.kind]}</span>`,
    iconSize: [32, 32],
    iconAnchor: [16, 16],
  });
}

function makeThreatIcon(threat: LiveThreat) {
  return L.divIcon({
    className: "",
    html: `<span class="map-marker map-marker--threat map-marker--threat-${threat.status}">${threatGlyph[threat.kind]}</span>`,
    iconSize: [28, 28],
    iconAnchor: [14, 14],
  });
}

function makeShotIcon() {
  return L.divIcon({
    className: "",
    html: `<span class="map-marker map-marker--shot"></span>`,
    iconSize: [16, 16],
    iconAnchor: [8, 8],
  });
}

function makeImpactIcon(marker: ImpactMarker) {
  return L.divIcon({
    className: "",
    html: `<span class="map-marker map-marker--${marker.tone}">${marker.tone === "impact" ? "!" : "*"}</span>`,
    iconSize: [30, 30],
    iconAnchor: [15, 15],
  });
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
      {game.liveThreats.map((threat) => {
        const current = threatPosition(threat);
        return (
          <Polyline
            key={`route-${threat.id}`}
            positions={[[current.lat, current.lng], [threat.target.lat, threat.target.lng]]}
            pathOptions={{ color: threat.detected ? "#ff7777" : "#f2c865", weight: 1, opacity: 0.42, dashArray: "5 7" }}
          />
        );
      })}
      {game.batteries.map((battery) => (
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
      ))}
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
            Coverage {battery.coverageTier} - readiness {Math.round(battery.readiness)}%
          </Tooltip>
        </Marker>
      ))}
      {game.liveThreats.map((threat) => {
        const current = threatPosition(threat);
        return (
          <Marker key={threat.id} position={[current.lat, current.lng]} icon={makeThreatIcon(threat)}>
            <Tooltip direction="top" offset={[0, -14]}>
              {threat.detected ? threat.kind : "unknown track"} - {threat.status}
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
