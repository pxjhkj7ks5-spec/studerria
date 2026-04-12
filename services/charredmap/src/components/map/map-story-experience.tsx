"use client";

import { useEffect, useState } from "react";
import type { FeatureCollection } from "geojson";
import { occupationMeta } from "@/lib/constants";
import type { SerializedStory } from "@/lib/data";
import { formatDate } from "@/lib/utils";
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

    document.body.style.overflow = "hidden";

    return () => {
      document.body.style.overflow = "";
    };
  }, [selectedStory]);

  return (
    <>
      <div className="glass-panel relative overflow-hidden rounded-[32px]">
        <div className="absolute inset-x-0 top-0 z-10 flex flex-col gap-3 border-b border-white/10 bg-[linear-gradient(180deg,rgba(0,0,0,0.72),rgba(0,0,0,0.16))] p-4 backdrop-blur-xl md:flex-row md:items-start md:justify-between">
          <div className="max-w-xl space-y-2">
            <p className="text-xs uppercase tracking-[0.28em] text-[--accent-orange]">
              Редакційний шар
            </p>
            <h2 className="font-display text-2xl text-white md:text-3xl">
              Темна мапа з мітками історій та помаранчевим контуром окупації
            </h2>
            <p className="text-sm leading-6 text-[--muted]">
              Помаранчевий полігон є редакційним GeoJSON-overlay для MVP і не претендує на оперативну точність у реальному часі.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs uppercase tracking-[0.2em] text-[--muted] sm:flex sm:flex-col sm:items-end">
            <span className="rounded-full border border-white/10 bg-black/30 px-3 py-2">
              {stories.length} історій на мапі
            </span>
            <span className="rounded-full border border-white/10 bg-black/30 px-3 py-2">
              Без реєстрації
            </span>
          </div>
        </div>

        <div className="grid min-h-[620px] grid-cols-1 xl:grid-cols-[minmax(0,1fr)_320px]">
          <MapCanvas
            stories={stories}
            occupationOverlay={occupationOverlay}
            onSelectStory={setSelectedStory}
          />

          <aside className="border-t border-white/10 bg-black/35 p-4 backdrop-blur-xl xl:border-t-0 xl:border-l">
            <div className="space-y-3">
              <p className="text-xs uppercase tracking-[0.28em] text-[--muted]">
                Опубліковані історії
              </p>
              <div className="space-y-2">
                {stories.length ? (
                  stories.map((story) => {
                    const meta = occupationMeta[story.city.occupationStatus];
                    const active = selectedStory?.id === story.id;

                    return (
                      <button
                        key={story.id}
                        type="button"
                        onClick={() => setSelectedStory(story)}
                        className={`w-full rounded-[24px] border px-4 py-3 text-left transition ${
                          active
                            ? "border-[--accent-orange]/55 bg-white/10"
                            : "border-white/8 bg-white/[0.035] hover:border-white/20 hover:bg-white/[0.06]"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-3">
                          <div className="min-w-0">
                            <p className="truncate font-semibold text-white">{story.title}</p>
                            <p className="mt-1 text-xs uppercase tracking-[0.16em] text-[--muted]">
                              {story.city.name} • {story.city.oblast}
                            </p>
                          </div>
                          <span
                            className={`h-3 w-3 shrink-0 rounded-full ${
                              story.city.occupationStatus === "occupied"
                                ? "bg-[--accent-orange]"
                                : "bg-white ring-2 ring-[rgba(218,59,59,0.8)]"
                            }`}
                          />
                        </div>
                        <p className="mt-2 text-xs text-[--muted]">
                          {meta.label} • {story.publishedAt ? formatDate(story.publishedAt) : "Без дати"}
                        </p>
                      </button>
                    );
                  })
                ) : (
                  <div className="rounded-[24px] border border-dashed border-white/12 bg-white/[0.03] p-5 text-sm text-[--muted]">
                    Після першої публікації тут з&apos;являться мітки і список матеріалів.
                  </div>
                )}
              </div>
            </div>
          </aside>
        </div>
      </div>

      {selectedStory ? (
        <div className="story-fade-in fixed inset-0 z-40 flex items-end justify-center bg-black/70 p-4 md:items-center">
          <div className="glass-panel max-h-[90vh] w-full max-w-4xl overflow-hidden rounded-[32px]">
            <StorySheet story={selectedStory} onClose={() => setSelectedStory(null)} compact />
          </div>
        </div>
      ) : null}
    </>
  );
}
