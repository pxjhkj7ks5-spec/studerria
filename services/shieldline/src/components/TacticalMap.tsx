import L from "leaflet";
import { Marker, TileLayer, Tooltip, MapContainer } from "react-leaflet";
import { useMemo } from "react";
import { useGameStore } from "../store/useGameStore";
import type { City, InfrastructureKind, InfrastructureNode } from "../types/game";

const mapCenter: [number, number] = [48.7, 31.4];

const nodeGlyph: Record<InfrastructureKind, string> = {
  energy: "E",
  logistics: "L",
  industry: "I",
  communications: "C",
};

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

export function TacticalMap() {
  const game = useGameStore((state) => state.game);
  const selectedCityId = useGameStore((state) => state.selectedCityId);
  const setSelectedCity = useGameStore((state) => state.setSelectedCity);

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
      <TileLayer
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        attribution="&copy; OpenStreetMap contributors"
      />
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
    </MapContainer>
  );
}
