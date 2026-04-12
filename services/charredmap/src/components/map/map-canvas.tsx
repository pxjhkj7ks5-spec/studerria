"use client";

import { useEffect, useEffectEvent, useRef } from "react";
import type { FeatureCollection } from "geojson";
import maplibregl from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import { mapStyleUrl, ukraineBounds } from "@/lib/constants";
import type { SerializedStory } from "@/lib/data";

type MapCanvasProps = {
  stories: SerializedStory[];
  occupationOverlay: FeatureCollection;
  onSelectStory: (story: SerializedStory) => void;
};

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

export function MapCanvas({ stories, occupationOverlay, onSelectStory }: MapCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const selectStory = useEffectEvent(onSelectStory);

  useEffect(() => {
    if (!containerRef.current) {
      return;
    }

    const map = new maplibregl.Map({
      container: containerRef.current,
      style: mapStyleUrl,
      center: [31.25, 48.8],
      zoom: 5.1,
      minZoom: 4.2,
      maxZoom: 11.5,
      maxBounds: ukraineBounds as unknown as maplibregl.LngLatBoundsLike,
      attributionControl: false,
    });

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
          markerElement.className =
            "group relative flex h-5 w-5 items-center justify-center rounded-full border border-white/35 bg-white/15 backdrop-blur-xl transition hover:scale-110";

          const innerDot = document.createElement("span");
          innerDot.className =
            story.city.occupationStatus === "occupied"
              ? "h-3 w-3 rounded-full bg-[--accent-orange] shadow-[0_0_18px_rgba(255,132,56,0.8)]"
              : "h-3 w-3 rounded-full bg-white ring-2 ring-[rgba(218,59,59,0.8)]";

          const pulse = document.createElement("span");
          pulse.className =
            "absolute inline-flex h-full w-full animate-ping rounded-full bg-white/12";

          markerElement.appendChild(pulse);
          markerElement.appendChild(innerDot);
          markerElement.addEventListener("click", () => selectStory(story));

          const coordinates = getOffsetPoint(story, index, cityStories.length);

          new maplibregl.Marker({
            element: markerElement,
            anchor: "center",
          })
            .setLngLat(coordinates)
            .addTo(map);
        });
      }
    });

    return () => {
      map.remove();
    };
  }, [occupationOverlay, selectStory, stories]);

  return <div ref={containerRef} className="h-full min-h-[480px] w-full" />;
}
