import type { Feature, FeatureCollection, Polygon, Position } from "geojson";

export type OccupationOverlayProperties = {
  id: string;
  region: string;
  note: string;
};

export type OccupationOverlayFeature = Feature<Polygon, OccupationOverlayProperties>;

const fallbackOverlay: FeatureCollection = {
  type: "FeatureCollection",
  features: [],
};

function closeLinearRing(points: Position[]) {
  if (!points.length) {
    return points;
  }

  const [firstLng, firstLat] = points[0];
  const [lastLng, lastLat] = points[points.length - 1];

  if (firstLng === lastLng && firstLat === lastLat) {
    return points;
  }

  return [...points, [firstLng, firstLat]];
}

function normalizeFeature(
  feature: Feature | null | undefined,
  index: number,
): OccupationOverlayFeature | null {
  if (!feature || feature.geometry?.type !== "Polygon") {
    return null;
  }

  const [outerRing] = feature.geometry.coordinates ?? [];
  if (!outerRing || outerRing.length < 3) {
    return null;
  }

  const cleanedRing = closeLinearRing(
    outerRing.filter(
      (position): position is Position =>
        Array.isArray(position) &&
        typeof position[0] === "number" &&
        typeof position[1] === "number",
    ),
  );

  if (cleanedRing.length < 4) {
    return null;
  }

  const properties = feature.properties ?? {};
  const region =
    typeof properties.region === "string" && properties.region.trim()
      ? properties.region.trim()
      : `Area ${index + 1}`;
  const note =
    typeof properties.note === "string" && properties.note.trim()
      ? properties.note.trim()
      : "";
  const id =
    typeof properties.id === "string" && properties.id.trim()
      ? properties.id.trim()
      : `overlay-${index + 1}`;

  return {
    type: "Feature",
    properties: {
      id,
      region,
      note,
    },
    geometry: {
      type: "Polygon",
      coordinates: [cleanedRing],
    },
  };
}

export function normalizeOccupationOverlay(
  value: FeatureCollection | null | undefined,
): FeatureCollection {
  if (!value || value.type !== "FeatureCollection" || !Array.isArray(value.features)) {
    return fallbackOverlay;
  }

  const features = value.features
    .map((feature, index) => normalizeFeature(feature, index))
    .filter((feature): feature is OccupationOverlayFeature => Boolean(feature));

  return {
    type: "FeatureCollection",
    features,
  };
}
