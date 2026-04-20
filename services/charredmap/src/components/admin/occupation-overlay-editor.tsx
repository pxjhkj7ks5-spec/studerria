"use client";

import { useEffect, useEffectEvent, useRef, useState } from "react";
import type { FeatureCollection, Position } from "geojson";
import maplibregl, { type GeoJSONSource } from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import { saveOccupationOverlayAction } from "@/app/actions/territories";
import { SubmitButton } from "@/components/admin/submit-button";
import { mapStyleUrl, ukraineBounds } from "@/lib/constants";
import {
  normalizeOccupationOverlay,
  type OccupationOverlayFeature,
} from "@/lib/occupation-overlay-shared";

type OccupationOverlayEditorProps = {
  overlay: FeatureCollection;
};

const relaxedUkraineBounds = [
  [ukraineBounds[0][0] - 4.8, ukraineBounds[0][1] - 3.4],
  [ukraineBounds[1][0] + 6.4, ukraineBounds[1][1] + 4.2],
] as const;

function createFeatureId() {
  return `overlay-${Math.random().toString(36).slice(2, 10)}`;
}

function closeRing(points: Position[]) {
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

function buildDraftOverlay(points: Position[]): FeatureCollection {
  const features: FeatureCollection["features"] = points.map((point, index) => ({
    type: "Feature",
    properties: {
      order: index + 1,
    },
    geometry: {
      type: "Point",
      coordinates: point,
    },
  }));

  if (points.length >= 2) {
    features.push({
      type: "Feature",
      properties: {},
      geometry: {
        type: "LineString",
        coordinates: points,
      },
    });
  }

  if (points.length >= 3) {
    features.push({
      type: "Feature",
      properties: {},
      geometry: {
        type: "Polygon",
        coordinates: [closeRing(points)],
      },
    });
  }

  return {
    type: "FeatureCollection",
    features,
  };
}

export function OccupationOverlayEditor({
  overlay,
}: OccupationOverlayEditorProps) {
  const [features, setFeatures] = useState<OccupationOverlayFeature[]>(
    normalizeOccupationOverlay(overlay).features as OccupationOverlayFeature[],
  );
  const [draftPoints, setDraftPoints] = useState<Position[]>([]);
  const [region, setRegion] = useState("");
  const [note, setNote] = useState("");
  const [selectedFeatureId, setSelectedFeatureId] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const featureClickRef = useRef(false);

  const normalizedOverlay = normalizeOccupationOverlay({
    type: "FeatureCollection",
    features,
  });

  const handleMapPointAdd = useEffectEvent((position: Position) => {
    setDraftPoints((current) => [...current, position]);
  });

  useEffect(() => {
    if (!containerRef.current || mapRef.current) {
      return;
    }

    const map = new maplibregl.Map({
      container: containerRef.current,
      style: mapStyleUrl,
      center: [32.4, 48.4],
      zoom: 4.6,
      minZoom: 3.85,
      maxZoom: 11.5,
      maxBounds: relaxedUkraineBounds as unknown as maplibregl.LngLatBoundsLike,
      attributionControl: false,
      renderWorldCopies: false,
    });

    mapRef.current = map;

    map.addControl(new maplibregl.NavigationControl({ visualizePitch: false }), "top-right");
    map.dragRotate.disable();
    map.touchZoomRotate.disableRotation();

    map.on("load", () => {
      map.addSource("admin-occupation-overlay", {
        type: "geojson",
        data: normalizedOverlay,
      });
      map.addSource("admin-occupation-selected", {
        type: "geojson",
        data: { type: "FeatureCollection", features: [] },
      });
      map.addSource("admin-occupation-draft", {
        type: "geojson",
        data: buildDraftOverlay([]),
      });

      map.addLayer({
        id: "admin-occupation-fill",
        type: "fill",
        source: "admin-occupation-overlay",
        paint: {
          "fill-color": "#ff8438",
          "fill-opacity": 0.22,
        },
      });
      map.addLayer({
        id: "admin-occupation-line",
        type: "line",
        source: "admin-occupation-overlay",
        paint: {
          "line-color": "#ffb178",
          "line-width": 1.25,
          "line-opacity": 0.9,
        },
      });
      map.addLayer({
        id: "admin-occupation-selected-line",
        type: "line",
        source: "admin-occupation-selected",
        paint: {
          "line-color": "#fff2dc",
          "line-width": 2.6,
          "line-opacity": 1,
        },
      });
      map.addLayer({
        id: "admin-occupation-draft-fill",
        type: "fill",
        source: "admin-occupation-draft",
        filter: ["==", ["geometry-type"], "Polygon"],
        paint: {
          "fill-color": "#ffb178",
          "fill-opacity": 0.12,
        },
      });
      map.addLayer({
        id: "admin-occupation-draft-line",
        type: "line",
        source: "admin-occupation-draft",
        filter: ["==", ["geometry-type"], "LineString"],
        paint: {
          "line-color": "#fff2dc",
          "line-width": 2,
          "line-dasharray": [1.1, 1.1],
        },
      });
      map.addLayer({
        id: "admin-occupation-draft-points",
        type: "circle",
        source: "admin-occupation-draft",
        filter: ["==", ["geometry-type"], "Point"],
        paint: {
          "circle-radius": 4.5,
          "circle-color": "#fff2dc",
          "circle-stroke-width": 2,
          "circle-stroke-color": "#ff8438",
        },
      });

      map.on("click", "admin-occupation-fill", (event) => {
        const clickedFeature = event.features?.[0];
        const featureId =
          typeof clickedFeature?.properties?.id === "string"
            ? clickedFeature.properties.id
            : null;

        if (featureId) {
          featureClickRef.current = true;
          setSelectedFeatureId(featureId);
        }
      });

      map.on("click", (event) => {
        if (featureClickRef.current) {
          featureClickRef.current = false;
          return;
        }

        handleMapPointAdd([event.lngLat.lng, event.lngLat.lat]);
      });
    });

    return () => {
      mapRef.current = null;
      map.remove();
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    if (!map?.isStyleLoaded()) {
      return;
    }

    (map.getSource("admin-occupation-overlay") as GeoJSONSource | undefined)?.setData(
      normalizedOverlay,
    );

    const selectedFeature =
      features.find((feature) => feature.properties.id === selectedFeatureId) ?? null;

    (map.getSource("admin-occupation-selected") as GeoJSONSource | undefined)?.setData({
      type: "FeatureCollection",
      features: selectedFeature ? [selectedFeature] : [],
    });

    (map.getSource("admin-occupation-draft") as GeoJSONSource | undefined)?.setData(
      buildDraftOverlay(draftPoints),
    );
  }, [draftPoints, features, normalizedOverlay, selectedFeatureId]);

  const selectedFeature =
    features.find((feature) => feature.properties.id === selectedFeatureId) ?? null;

  const createPolygon = () => {
    if (draftPoints.length < 3) {
      return;
    }

    const nextFeature: OccupationOverlayFeature = {
      type: "Feature",
      properties: {
        id: createFeatureId(),
        region: region.trim() || `Area ${features.length + 1}`,
        note: note.trim(),
      },
      geometry: {
        type: "Polygon",
        coordinates: [closeRing(draftPoints)],
      },
    };

    setFeatures((current) => [...current, nextFeature]);
    setSelectedFeatureId(nextFeature.properties.id);
    setDraftPoints([]);
    setRegion("");
    setNote("");
  };

  const removeFeature = (featureId: string) => {
    setFeatures((current) => current.filter((feature) => feature.properties.id !== featureId));
    setSelectedFeatureId((current) => (current === featureId ? null : current));
  };

  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1.35fr)_360px]">
      <div className="glass-panel overflow-hidden rounded-[30px]">
        <div className="border-b border-white/10 px-5 py-4">
          <p className="text-xs uppercase tracking-[0.28em] text-[--accent-orange]">
            Occupied Territories
          </p>
          <h1 className="mt-2 font-display text-3xl text-white">Ручне креслення територій</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-white/72">
            Кожен клік по мапі додає вершину. Коли точок достатньо, завершіть полігон і збережіть
            overlay.
          </p>
        </div>

        <div ref={containerRef} className="h-[36rem] w-full md:h-[44rem] xl:h-[48rem]" />
      </div>

      <div className="space-y-4">
        <form action={saveOccupationOverlayAction} className="glass-panel rounded-[28px] p-5">
          <input
            type="hidden"
            name="overlayGeoJson"
            value={JSON.stringify(normalizedOverlay)}
          />

          <p className="text-xs uppercase tracking-[0.26em] text-[--accent-orange]">
            Чернетка полігона
          </p>
          <div className="mt-4 space-y-4">
            <label className="block space-y-2">
              <span className="text-sm text-[--muted]">Назва області</span>
              <input
                value={region}
                onChange={(event) => setRegion(event.target.value)}
                placeholder="Наприклад, Запорізький сектор"
                className="w-full rounded-[18px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
              />
            </label>

            <label className="block space-y-2">
              <span className="text-sm text-[--muted]">Нотатка</span>
              <textarea
                value={note}
                onChange={(event) => setNote(event.target.value)}
                rows={3}
                placeholder="Короткий редакційний опис"
                className="w-full rounded-[20px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
              />
            </label>

            <div className="rounded-[22px] border border-white/8 bg-white/[0.03] p-4">
              <p className="text-[11px] uppercase tracking-[0.2em] text-[--muted]">
                Точки в чернетці
              </p>
              <p className="mt-2 font-display text-3xl text-white">
                {String(draftPoints.length).padStart(2, "0")}
              </p>
              <p className="mt-2 text-sm leading-6 text-white/68">
                Мінімум 3 точки для полігона. Клік по мапі додає вершину в кінець.
              </p>
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => setDraftPoints((current) => current.slice(0, -1))}
                disabled={!draftPoints.length}
                className="rounded-full border border-white/12 px-4 py-2 text-sm text-white transition disabled:cursor-not-allowed disabled:opacity-40 hover:border-white/30"
              >
                Прибрати точку
              </button>
              <button
                type="button"
                onClick={() => setDraftPoints([])}
                disabled={!draftPoints.length}
                className="rounded-full border border-white/12 px-4 py-2 text-sm text-white transition disabled:cursor-not-allowed disabled:opacity-40 hover:border-white/30"
              >
                Очистити
              </button>
              <button
                type="button"
                onClick={createPolygon}
                disabled={draftPoints.length < 3}
                className="rounded-full border border-[--accent-orange]/30 bg-[rgba(255,132,56,0.14)] px-4 py-2 text-sm text-[--accent-ember] transition disabled:cursor-not-allowed disabled:opacity-40 hover:border-[--accent-orange]/55"
              >
                Створити полігон
              </button>
            </div>

            <div className="border-t border-white/10 pt-4">
              <SubmitButton variant="accent" pendingLabel="Збереження...">
                Зберегти території
              </SubmitButton>
            </div>
          </div>
        </form>

        <div className="glass-panel rounded-[28px] p-5">
          <p className="text-xs uppercase tracking-[0.26em] text-[--accent-orange]">
            Збережені області
          </p>
          <div className="mt-4 space-y-3">
            {features.length ? (
              features.map((feature) => (
                <div
                  key={feature.properties.id}
                  className={`rounded-[22px] border p-4 transition ${
                    selectedFeatureId === feature.properties.id
                      ? "border-[--accent-orange]/40 bg-[rgba(255,132,56,0.09)]"
                      : "border-white/10 bg-white/[0.03]"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <button
                      type="button"
                      onClick={() => setSelectedFeatureId(feature.properties.id)}
                      className="min-w-0 text-left"
                    >
                      <p className="font-medium text-white">{feature.properties.region}</p>
                      <p className="mt-1 text-xs uppercase tracking-[0.18em] text-[--muted]">
                        {feature.geometry.coordinates[0].length - 1} точок
                      </p>
                    </button>
                    <button
                      type="button"
                      onClick={() => removeFeature(feature.properties.id)}
                      className="rounded-full border border-white/10 px-3 py-1 text-xs text-[--muted] transition hover:border-[--accent-red]/40 hover:text-white"
                    >
                      Видалити
                    </button>
                  </div>

                  {feature.properties.note ? (
                    <p className="mt-3 text-sm leading-6 text-white/68">{feature.properties.note}</p>
                  ) : null}
                </div>
              ))
            ) : (
              <div className="rounded-[22px] border border-dashed border-white/12 bg-white/[0.03] p-4 text-sm text-[--muted]">
                Overlay ще порожній.
              </div>
            )}
          </div>

          {selectedFeature ? (
            <div className="mt-4 rounded-[22px] border border-white/10 bg-black/20 p-4">
              <p className="text-[11px] uppercase tracking-[0.2em] text-[--muted]">
                Вибрана область
              </p>
              <p className="mt-2 text-white">{selectedFeature.properties.region}</p>
              {selectedFeature.properties.note ? (
                <p className="mt-2 text-sm leading-6 text-white/68">
                  {selectedFeature.properties.note}
                </p>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
