"use client";

import { useEffect, useMemo, useRef } from "react";
import type { FeatureCollection } from "geojson";
import maplibregl from "maplibre-gl";
import type { AtlasMarker, AtlasPeriod } from "@/lib/atlas-data";
import { toFeatureCollection } from "@/lib/atlas-data";

type MapCanvasProps = {
  period: AtlasPeriod;
  showControl: boolean;
  showClaims: boolean;
  showEvents: boolean;
};

type MarkerRecord = {
  marker: maplibregl.Marker;
  element: HTMLButtonElement;
};

const CONTROL_SOURCE_ID = "atlas-control";
const CLAIM_SOURCE_ID = "atlas-claims";
const CONTROL_FILL_LAYER_ID = "atlas-control-fill";
const CONTROL_LINE_LAYER_ID = "atlas-control-line";
const CLAIM_FILL_LAYER_ID = "atlas-claims-fill";
const CLAIM_LINE_LAYER_ID = "atlas-claims-line";

const emptyCollection: FeatureCollection = {
  type: "FeatureCollection",
  features: [],
};

function buildStyle(): maplibregl.StyleSpecification {
  return {
    version: 8,
    sources: {},
    layers: [
      {
        id: "atlas-background",
        type: "background",
        paint: {
          "background-color": "#eeece1",
        },
      },
    ],
  };
}

function buildPopup(marker: AtlasMarker) {
  const wrapper = document.createElement("div");
  wrapper.className = "atlas-popup";

  const kicker = document.createElement("p");
  kicker.className = "atlas-popup__kicker";
  kicker.textContent = marker.kicker;

  const title = document.createElement("p");
  title.className = "atlas-popup__title";
  title.textContent = marker.title;

  const body = document.createElement("p");
  body.className = "atlas-popup__body";
  body.textContent = marker.summary;

  wrapper.append(kicker, title, body);
  return wrapper;
}

function ensureLayers(map: maplibregl.Map) {
  if (!map.getSource(CONTROL_SOURCE_ID)) {
    map.addSource(CONTROL_SOURCE_ID, {
      type: "geojson",
      data: emptyCollection,
    });
  }

  if (!map.getSource(CLAIM_SOURCE_ID)) {
    map.addSource(CLAIM_SOURCE_ID, {
      type: "geojson",
      data: emptyCollection,
    });
  }

  if (!map.getLayer(CONTROL_FILL_LAYER_ID)) {
    map.addLayer({
      id: CONTROL_FILL_LAYER_ID,
      type: "fill",
      source: CONTROL_SOURCE_ID,
      paint: {
        "fill-color": [
          "match",
          ["get", "tone"],
          "separate",
          "#9bbb59",
          "colonial",
          "#c0504d",
          "#4f81bd",
        ],
        "fill-opacity": [
          "match",
          ["get", "tone"],
          "colonial",
          0.48,
          "separate",
          0.38,
          0.42,
        ],
      },
    });
  }

  if (!map.getLayer(CONTROL_LINE_LAYER_ID)) {
    map.addLayer({
      id: CONTROL_LINE_LAYER_ID,
      type: "line",
      source: CONTROL_SOURCE_ID,
      paint: {
        "line-color": "#1f497d",
        "line-width": 1.45,
        "line-opacity": 0.72,
      },
    });
  }

  if (!map.getLayer(CLAIM_FILL_LAYER_ID)) {
    map.addLayer({
      id: CLAIM_FILL_LAYER_ID,
      type: "fill",
      source: CLAIM_SOURCE_ID,
      paint: {
        "fill-color": [
          "match",
          ["get", "tone"],
          "separate",
          "#9bbb59",
          "colonial",
          "#c0504d",
          "#c0504d",
        ],
        "fill-opacity": 0.22,
      },
    });
  }

  if (!map.getLayer(CLAIM_LINE_LAYER_ID)) {
    map.addLayer({
      id: CLAIM_LINE_LAYER_ID,
      type: "line",
      source: CLAIM_SOURCE_ID,
      paint: {
        "line-color": "#c0504d",
        "line-width": 1.65,
        "line-opacity": 0.88,
        "line-dasharray": [2, 2],
      },
    });
  }
}

function setLayerVisibility(map: maplibregl.Map, layerIds: string[], visible: boolean) {
  layerIds.forEach((layerId) => {
    if (map.getLayer(layerId)) {
      map.setLayoutProperty(layerId, "visibility", visible ? "visible" : "none");
    }
  });
}

function clearMarkers(markers: MarkerRecord[]) {
  markers.forEach(({ marker }) => marker.remove());
  markers.length = 0;
}

function mountMarkers(
  map: maplibregl.Map,
  markers: MarkerRecord[],
  periodMarkers: AtlasMarker[],
) {
  clearMarkers(markers);
  const popup = new maplibregl.Popup({
    closeButton: false,
    closeOnClick: false,
    offset: 18,
    maxWidth: "320px",
  });

  periodMarkers.forEach((periodMarker) => {
    const element = document.createElement("button");
    element.type = "button";
    element.className = "atlas-marker";
    element.dataset.kind = periodMarker.kind;
    element.setAttribute("aria-label", `${periodMarker.kicker}: ${periodMarker.title}`);

    const dot = document.createElement("span");
    dot.className = "atlas-marker__dot";
    element.append(dot);

    const showPopup = () => {
      popup
        .setLngLat(periodMarker.coordinates)
        .setDOMContent(buildPopup(periodMarker))
        .addTo(map);
    };
    const hidePopup = () => popup.remove();

    element.addEventListener("mouseenter", showPopup);
    element.addEventListener("focus", showPopup);
    element.addEventListener("mouseleave", hidePopup);
    element.addEventListener("blur", hidePopup);
    element.addEventListener("click", showPopup);

    const marker = new maplibregl.Marker({
      element,
      anchor: "center",
    })
      .setLngLat(periodMarker.coordinates)
      .addTo(map);

    markers.push({ marker, element });
  });
}

export function MapCanvas({
  period,
  showControl,
  showClaims,
  showEvents,
}: MapCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const loadedRef = useRef(false);
  const markersRef = useRef<MarkerRecord[]>([]);
  const initialBoundsRef = useRef(period.bounds);

  const controlledCollection = useMemo(() => toFeatureCollection(period.controlled), [period]);
  const claimCollection = useMemo(() => toFeatureCollection(period.claims), [period]);

  useEffect(() => {
    if (!containerRef.current || mapRef.current) return;

    const map = new maplibregl.Map({
      container: containerRef.current,
      style: buildStyle(),
      center: [104, 31],
      zoom: 2.75,
      minZoom: 2,
      maxZoom: 7,
      attributionControl: false,
    });

    map.addControl(
      new maplibregl.NavigationControl({
        showCompass: false,
      }),
      "bottom-left",
    );

    map.on("load", () => {
      loadedRef.current = true;
      ensureLayers(map);
      map.fitBounds(initialBoundsRef.current, {
        padding: 44,
        duration: 0,
      });
    });

    mapRef.current = map;

    const activeMarkers = markersRef.current;

    return () => {
      clearMarkers(activeMarkers);
      map.remove();
      mapRef.current = null;
      loadedRef.current = false;
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || !loadedRef.current) return;

    ensureLayers(map);
    const controlSource = map.getSource(CONTROL_SOURCE_ID) as maplibregl.GeoJSONSource | undefined;
    const claimSource = map.getSource(CLAIM_SOURCE_ID) as maplibregl.GeoJSONSource | undefined;
    controlSource?.setData(controlledCollection);
    claimSource?.setData(claimCollection);

    map.fitBounds(period.bounds, {
      padding: { top: 78, right: 40, bottom: 40, left: 40 },
      duration: 620,
      essential: true,
    });
  }, [claimCollection, controlledCollection, period]);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || !loadedRef.current) return;

    setLayerVisibility(map, [CONTROL_FILL_LAYER_ID, CONTROL_LINE_LAYER_ID], showControl);
    setLayerVisibility(map, [CLAIM_FILL_LAYER_ID, CLAIM_LINE_LAYER_ID], showClaims);
  }, [showClaims, showControl]);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || !loadedRef.current) return;

    if (!showEvents) {
      clearMarkers(markersRef.current);
      return;
    }

    mountMarkers(map, markersRef.current, period.markers);
  }, [period, showEvents]);

  return (
    <>
      <div ref={containerRef} className="atlas-map" aria-label="Interactive China border atlas map" />
      <div className="atlas-map-topline">
        <div className="atlas-map-pill">Approximate classroom map · de facto + claims</div>
        <div className="atlas-map-pill">{period.label} · {period.range}</div>
      </div>
    </>
  );
}
