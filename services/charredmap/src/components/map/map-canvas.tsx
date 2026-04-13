"use client";

import { useEffect, useEffectEvent, useRef } from "react";
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
  onPreviewStory?: (story: SerializedStory) => void;
};

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
  eyebrow.textContent = story.city.occupationStatus === "occupied" ? "Окуповане місто" : "Деокуповане місто";

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

export function MapCanvas({
  stories,
  occupationOverlay,
  activeStory = null,
  onSelectStory,
  onPreviewStory,
}: MapCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const markerElementsRef = useRef<Map<string, HTMLButtonElement>>(new Map());
  const popupRef = useRef<maplibregl.Popup | null>(null);
  const activeStoryRef = useRef<SerializedStory | null>(activeStory);
  const selectStory = useEffectEvent(onSelectStory);
  const previewStory = useEffectEvent((story: SerializedStory) => {
    onPreviewStory?.(story);
  });

  function syncActiveMarkerState(activeId: string | null) {
    for (const [storyId, element] of markerElementsRef.current) {
      element.dataset.selected = storyId === activeId ? "true" : "false";
    }
  }

  useEffect(() => {
    activeStoryRef.current = activeStory;
    syncActiveMarkerState(activeStory?.id ?? null);
  }, [activeStory]);

  useEffect(() => {
    if (!containerRef.current) {
      return;
    }

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

    map.on("load", () => {
      map.addSource("occupation-overlay", {
        type: "geojson",
        data: occupationOverlay,
      });

      map.addLayer({
        id: "occupation-fill",
        type: "fill",
        source: "occupation-overlay",
        paint: {
          "fill-color": "#ff8438",
          "fill-opacity": 0.22,
        },
      });

      map.addLayer({
        id: "occupation-line",
        type: "line",
        source: "occupation-overlay",
        paint: {
          "line-color": "#ffb178",
          "line-width": 1.25,
          "line-opacity": 0.85,
        },
      });

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

      const storiesByCity = new Map<string, SerializedStory[]>();
      const markerElements = new Map<string, HTMLButtonElement>();

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
          markerElement.setAttribute(
            "aria-label",
            `${story.title}. ${story.city.name}, ${story.city.oblast}.`,
          );

          const innerDot = document.createElement("span");
          innerDot.className = "charredmap-marker__dot";

          const pulse = document.createElement("span");
          pulse.className = "charredmap-marker__pulse";

          markerElement.appendChild(pulse);
          markerElement.appendChild(innerDot);

          const coordinates = getOffsetPoint(story, index, cityStories.length);
          const openPreview = () => {
            previewStory(story);

            if (!canHover) {
              return;
            }

            popup
              .setLngLat(coordinates)
              .setDOMContent(buildPopupContent(story))
              .addTo(map);
          };

          markerElement.addEventListener("mouseenter", openPreview);
          markerElement.addEventListener("focus", openPreview);
          markerElement.addEventListener("mouseleave", () => popup.remove());
          markerElement.addEventListener("blur", () => popup.remove());
          markerElement.addEventListener("click", () => {
            previewStory(story);
            selectStory(story);
          });

          new maplibregl.Marker({
            element: markerElement,
            anchor: "center",
          })
            .setLngLat(coordinates)
            .addTo(map);

          markerElements.set(story.id, markerElement);
        });
      }

      markerElementsRef.current = markerElements;
      syncActiveMarkerState(activeStoryRef.current?.id ?? null);
    });

    return () => {
      popupRef.current?.remove();
      popupRef.current = null;
      markerElementsRef.current.clear();
      mapRef.current = null;
      map.remove();
    };
  }, [occupationOverlay, previewStory, selectStory, stories]);

  return <div ref={containerRef} className="h-full min-h-[560px] w-full xl:min-h-[46rem] 2xl:min-h-[50rem]" />;
}
