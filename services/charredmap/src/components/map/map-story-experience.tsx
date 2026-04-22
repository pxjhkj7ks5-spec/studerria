"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import type { FeatureCollection } from "geojson";
import type { SerializedStory } from "@/lib/data";
import { MapCanvas } from "@/components/map/map-canvas";
import { StorySheet } from "@/components/story/story-sheet";

type MapStoryExperienceProps = {
  stories: SerializedStory[];
  occupationOverlay: FeatureCollection;
};

export function MapStoryExperience({
  stories,
  occupationOverlay,
}: MapStoryExperienceProps) {
  const [selectedStory, setSelectedStory] = useState<SerializedStory | null>(null);
  const [portalNode, setPortalNode] = useState<HTMLElement | null>(null);
  const closeStory = () => setSelectedStory(null);

  useEffect(() => {
    setPortalNode(document.body);
  }, []);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setSelectedStory(null);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (!selectedStory) {
      return;
    }

    const initialBodyOverflow = document.body.style.overflow;
    const initialHtmlOverflow = document.documentElement.style.overflow;
    document.body.style.overflow = "hidden";
    document.documentElement.style.overflow = "hidden";

    return () => {
      document.body.style.overflow = initialBodyOverflow;
      document.documentElement.style.overflow = initialHtmlOverflow;
    };
  }, [selectedStory]);

  return (
    <>
      <div className="glass-panel relative w-full overflow-hidden rounded-[36px] xl:rounded-[40px]">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(255,132,56,0.16),_transparent_28%),radial-gradient(circle_at_86%_14%,_rgba(255,255,255,0.08),_transparent_18%),linear-gradient(180deg,rgba(255,255,255,0.05),transparent_32%)]" />

        <div className="relative border-b border-white/10 px-4 py-4 md:px-5 md:py-4 xl:px-6">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
            <div className="max-w-[34rem] space-y-3">
              <p className="text-[11px] uppercase tracking-[0.3em] text-[--accent-orange]">
                Мапа історій
              </p>
              <h2 className="font-display text-2xl leading-[1.02] text-white md:text-[2rem]">
                Натисніть на мітку, щоб відкрити історію.
              </h2>
            </div>

            <div className="flex flex-wrap gap-2 text-[11px] uppercase tracking-[0.18em] text-[--muted]">
              <span className="rounded-full border border-white/10 bg-black/25 px-3 py-2">
                {stories.length} матеріалів
              </span>
              <span className="rounded-full border border-white/10 bg-black/25 px-3 py-2">Натисніть на мітку</span>
            </div>
          </div>
        </div>

        <div className="relative min-h-[700px] 2xl:min-h-[50rem]">
          <div className="relative min-h-[560px] xl:min-h-[46rem] 2xl:min-h-[50rem]">
            <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(180deg,rgba(0,0,0,0.04),rgba(0,0,0,0.3))]" />

            <MapCanvas
              stories={stories}
              occupationOverlay={occupationOverlay}
              activeStory={selectedStory}
              onSelectStory={setSelectedStory}
            />
          </div>
        </div>
      </div>

      {portalNode && selectedStory
        ? createPortal(
          <>
            <div
              className="story-fade-in fixed inset-0 z-[80] bg-[rgba(3,4,6,0.76)] backdrop-blur-sm"
              onClick={closeStory}
              role="presentation"
            />
            <div className="story-fade-in pointer-events-none fixed inset-0 z-[81] grid place-items-center p-3 sm:p-4 md:p-6">
              <div
                className="pointer-events-auto glass-panel flex h-[min(92dvh,960px)] min-h-0 w-full max-w-[1100px] overflow-hidden rounded-[30px] shadow-[0_36px_120px_rgba(0,0,0,0.5)] sm:rounded-[34px]"
                onClick={(event) => event.stopPropagation()}
                role="presentation"
              >
                <StorySheet story={selectedStory} onClose={closeStory} compact />
              </div>
            </div>
          </>
          ,
          portalNode,
        )
        : null}
    </>
  );
}
