"use client";

import { useEffect, useRef } from "react";
import type { FeatureCollection } from "geojson";
import maplibregl from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import { mapStyleUrl, ukraineBounds } from "@/lib/constants";
import type { SerializedStory } from "@/lib/data";
import { formatDate } from "@/lib/utils";

type MapCanvasProps = {
  stories: SerializedStory[];
  occupationOverlay: FeatureCollection;
  activeStory?: SerializedStory | null;
  onSelectStory: (story: SerializedStory) => void;
};

type MarkerRecord = {
  marker: maplibregl.Marker;
  element: HTMLButtonElement;
  storyId: string;
};

const OVERLAY_SOURCE_ID = "occupation-overlay";
const OVERLAY_FILL_LAYER_ID = "occupation-fill";
const OVERLAY_LINE_LAYER_ID = "occupation-line";

const relaxedUkraineBounds = [
  [ukraineBounds[0][0] - 4.8, ukraineBounds[0][1] - 3.4],
  [ukraineBounds[1][0] + 6.4, ukraineBounds[1][1] + 4.2],
] as const;

function getOffsetPoint(story: SerializedStory, index: number, total: number) {
  if (total <= 1) {
    return [story.city.lng, story.city.lat] as [number, number];
  }

  const angle = (index / total) * Math.PI * 2;
  const radius = 0.22;

  return [
    story.city.lng + Math.cos(angle) * radius,
    story.city.lat + Math.sin(angle) * radius * 0.7,
  ] as [number, number];
}

function buildPopupContent(story: SerializedStory) {
  const wrapper = document.createElement("div");
  wrapper.className = "charredmap-map-popup__body";

  const eyebrow = document.createElement("p");
  eyebrow.className = "charredmap-map-popup__eyebrow";
  eyebrow.textContent =
    story.city.occupationStatus === "occupied" ? "Окуповане місто" : "Деокуповане місто";

  const title = document.createElement("p");
  title.className = "charredmap-map-popup__title";
  title.textContent = story.title;

  const meta = document.createElement("p");
  meta.className = "charredmap-map-popup__meta";
  meta.textContent = `${story.city.name} • ${story.city.oblast} • ${story.publishedAt ? formatDate(story.publishedAt) : "Без дати"}`;

  wrapper.appendChild(eyebrow);
  wrapper.appendChild(title);
  wrapper.appendChild(meta);

  return wrapper;
}

function syncActiveMarkerState(markerElements: Map<string, HTMLButtonElement>, activeId: string | null) {
  for (const [storyId, element] of markerElements) {
    element.dataset.selected = storyId === activeId ? "true" : "false";
  }
}

function clearMarkers(markers: MarkerRecord[]) {
  markers.forEach(({ marker }) => marker.remove());
  markers.length = 0;
}

function ensureOverlayLayers(map: maplibregl.Map, occupationOverlay: FeatureCollection) {
  const overlaySource = map.getSource(OVERLAY_SOURCE_ID) as maplibregl.GeoJSONSource | undefined;

  if (overlaySource) {
    overlaySource.setData(occupationOverlay);
  } else {
    map.addSource(OVERLAY_SOURCE_ID, {
      type: "geojson",
      data: occupationOverlay,
    });
  }

  if (!map.getLayer(OVERLAY_FILL_LAYER_ID)) {
    map.addLayer({
      id: OVERLAY_FILL_LAYER_ID,
      type: "fill",
      source: OVERLAY_SOURCE_ID,
      paint: {
        "fill-color": "#ff8438",
        "fill-opacity": 0.22,
      },
    });
  }

  if (!map.getLayer(OVERLAY_LINE_LAYER_ID)) {
    map.addLayer({
      id: OVERLAY_LINE_LAYER_ID,
      type: "line",
      source: OVERLAY_SOURCE_ID,
      paint: {
        "line-color": "#ffb178",
        "line-width": 1.25,
        "line-opacity": 0.85,
      },
    });
  }
}

function mountMarkers(
  map: maplibregl.Map,
  stories: SerializedStory[],
  popup: maplibregl.Popup,
  canHover: boolean,
  markers: MarkerRecord[],
  markerElements: Map<string, HTMLButtonElement>,
  onSelectStory: (story: SerializedStory) => void,
) {
  clearMarkers(markers);
  markerElements.clear();

  const storiesByCity = new Map<string, SerializedStory[]>();

  for (const story of stories) {
    const existing = storiesByCity.get(story.city.id) ?? [];
    existing.push(story);
    storiesByCity.set(story.city.id, existing);
  }

  for (const [, cityStories] of storiesByCity) {
    cityStories.forEach((story, index) => {
      const markerElement = document.createElement("button");
      markerElement.type = "button";
      markerElement.className = "charredmap-marker";
      markerElement.dataset.occupation = story.city.occupationStatus;
      markerElement.dataset.selected = "false";
      markerElement.setAttribute("aria-label", `${story.title}. ${story.city.name}, ${story.city.oblast}.`);

      const innerDot = document.createElement("span");
      innerDot.className = "charredmap-marker__dot";

      const pulse = document.createElement("span");
      pulse.className = "charredmap-marker__pulse";

      markerElement.appendChild(pulse);
      markerElement.appendChild(innerDot);

      const coordinates = getOffsetPoint(story, index, cityStories.length);
      const showPopup = () => {
        if (!canHover) {
          return;
        }

        popup
          .setLngLat(coordinates)
          .setDOMContent(buildPopupContent(story))
          .addTo(map);
      };

      const hidePopup = () => {
        popup.remove();
      };

      markerElement.addEventListener("mouseenter", showPopup);
      markerElement.addEventListener("focus", showPopup);
      markerElement.addEventListener("mouseleave", hidePopup);
      markerElement.addEventListener("blur", hidePopup);
      markerElement.addEventListener("click", () => {
        hidePopup();
        onSelectStory(story);
      });

      const marker = new maplibregl.Marker({
        element: markerElement,
        anchor: "center",
      })
        .setLngLat(coordinates)
        .addTo(map);

      markers.push({
        marker,
        element: markerElement,
        storyId: story.id,
      });
      markerElements.set(story.id, markerElement);
    });
  }
}

export function MapCanvas({
  stories,
  occupationOverlay,
  activeStory = null,
  onSelectStory,
}: MapCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const popupRef = useRef<maplibregl.Popup | null>(null);
  const mapLoadedRef = useRef(false);
  const markersRef = useRef<MarkerRecord[]>([]);
  const markerElementsRef = useRef<Map<string, HTMLButtonElement>>(new Map());

  const activeStoryRef = useRef<SerializedStory | null>(activeStory);
  const latestStoriesRef = useRef(stories);
  const latestOverlayRef = useRef(occupationOverlay);
  const latestOnSelectStoryRef = useRef(onSelectStory);

  useEffect(() => {
    latestOnSelectStoryRef.current = onSelectStory;
  }, [onSelectStory]);

  useEffect(() => {
    activeStoryRef.current = activeStory;
    syncActiveMarkerState(markerElementsRef.current, activeStory?.id ?? null);
  }, [activeStory]);

  useEffect(() => {
    latestStoriesRef.current = stories;

    const map = mapRef.current;
    const popup = popupRef.current;

    if (!map || !popup || !mapLoadedRef.current) {
      return;
    }

    const canHover = window.matchMedia("(hover: hover)").matches;
    mountMarkers(
      map,
      stories,
      popup,
      canHover,
      markersRef.current,
      markerElementsRef.current,
      (story) => latestOnSelectStoryRef.current(story),
    );
    syncActiveMarkerState(markerElementsRef.current, activeStoryRef.current?.id ?? null);
  }, [stories]);

  useEffect(() => {
    latestOverlayRef.current = occupationOverlay;

    const map = mapRef.current;
    if (!map || !mapLoadedRef.current) {
      return;
    }

    ensureOverlayLayers(map, occupationOverlay);
  }, [occupationOverlay]);

  useEffect(() => {
    if (!containerRef.current || mapRef.current) {
      return;
    }

    const markers = markersRef.current;
    const markerElements = markerElementsRef.current;

    const map = new maplibregl.Map({
      container: containerRef.current,
      style: mapStyleUrl,
      center: [31.4, 48.7],
      zoom: 4.65,
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

    const canHover = window.matchMedia("(hover: hover)").matches;
    const popup = new maplibregl.Popup({
      closeButton: false,
      closeOnClick: false,
      closeOnMove: false,
      focusAfterOpen: false,
      offset: 18,
      className: "charredmap-map-popup",
      maxWidth: "280px",
    });
    popupRef.current = popup;

    const handleLoad = () => {
      mapLoadedRef.current = true;
      ensureOverlayLayers(map, latestOverlayRef.current);
      mountMarkers(
        map,
        latestStoriesRef.current,
        popup,
        canHover,
        markers,
        markerElements,
        (story) => latestOnSelectStoryRef.current(story),
      );
      syncActiveMarkerState(markerElements, activeStoryRef.current?.id ?? null);
    };

    map.on("load", handleLoad);

    return () => {
      map.off("load", handleLoad);
      mapLoadedRef.current = false;
      popup.remove();
      popupRef.current = null;
      clearMarkers(markers);
      markerElements.clear();
      map.remove();
      mapRef.current = null;
    };
  }, []);

  return <div ref={containerRef} className="h-full min-h-[560px] w-full xl:min-h-[46rem] 2xl:min-h-[50rem]" />;
}
