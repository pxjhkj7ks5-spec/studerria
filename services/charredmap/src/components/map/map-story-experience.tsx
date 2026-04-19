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
  const [activeStory, setActiveStory] = useState<SerializedStory | null>(stories[0] ?? null);

  useEffect(() => {
    if (!stories.length) {
      setActiveStory(null);
      return;
    }

    setActiveStory((current) => {
      if (current && stories.some((entry) => entry.id === current.id)) {
        return current;
      }

      return stories[0] ?? null;
    });
  }, [stories]);

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
      <div className="glass-panel relative w-full overflow-hidden rounded-[36px] xl:rounded-[40px]">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(255,132,56,0.16),_transparent_28%),radial-gradient(circle_at_86%_14%,_rgba(255,255,255,0.08),_transparent_18%),linear-gradient(180deg,rgba(255,255,255,0.05),transparent_32%)]" />
        <div className="pointer-events-none absolute inset-y-0 right-[304px] hidden w-px bg-[linear-gradient(180deg,transparent,rgba(255,255,255,0.12),transparent)] xl:block 2xl:right-[328px]" />

        <div className="relative border-b border-white/10 px-4 py-4 md:px-5 md:py-4 xl:px-6">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
            <div className="max-w-[34rem] space-y-3">
              <p className="text-[11px] uppercase tracking-[0.3em] text-[--accent-orange]">
                Редакційний шар
              </p>
              <h2 className="font-display text-2xl leading-[1.02] text-white md:text-[2rem]">
                Карта лишається сценою, а історія входить у кадр тільки після вибору мітки.
              </h2>
            </div>

            <div className="flex flex-wrap gap-2 text-[11px] uppercase tracking-[0.18em] text-[--muted]">
              <span className="rounded-full border border-white/10 bg-black/25 px-3 py-2">
                {stories.length} матеріалів
              </span>
              <span className="rounded-full border border-white/10 bg-black/25 px-3 py-2">
                Курсор або натиск
              </span>
            </div>
          </div>
        </div>

        <div className="relative grid min-h-[700px] grid-cols-1 xl:min-h-[46rem] xl:grid-cols-[minmax(0,1.18fr)_304px] 2xl:min-h-[50rem] 2xl:grid-cols-[minmax(0,1.28fr)_328px]">
          <div className="relative min-h-[560px] border-b border-white/10 xl:min-h-[46rem] xl:border-b-0 2xl:min-h-[50rem]">
            <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(180deg,rgba(0,0,0,0.04),rgba(0,0,0,0.3))]" />
            {activeStory ? (
              <div className="pointer-events-none absolute left-5 top-5 z-10 hidden max-w-[19rem] xl:block 2xl:max-w-[21rem]">
                <div className="rounded-[28px] border border-white/10 bg-[rgba(7,9,12,0.68)] p-5 shadow-[0_30px_80px_rgba(0,0,0,0.34)] backdrop-blur-2xl">
                  <p className="text-[11px] uppercase tracking-[0.28em] text-[--accent-orange]">
                    У фокусі
                  </p>
                  <h3 className="mt-3 font-display text-2xl leading-[1.02] text-white">
                    {activeStory.title}
                  </h3>
                  <p className="mt-3 text-sm leading-6 text-white/78">
                    {activeStory.excerpt}
                  </p>
                  <div className="mt-4 flex flex-wrap gap-2 text-[11px] uppercase tracking-[0.18em] text-[--muted]">
                    <span className="rounded-full border border-white/10 bg-black/25 px-3 py-1">
                      {activeStory.city.name}
                    </span>
                    <span className="rounded-full border border-white/10 bg-black/25 px-3 py-1">
                      {activeStory.city.occupationStatus === "occupied" ? "Окуповане" : "Деокуповане"}
                    </span>
                  </div>
                </div>
              </div>
            ) : null}
            <div className="pointer-events-none absolute inset-x-0 bottom-0 z-10 p-4 md:p-6">
              <div className="max-w-md rounded-[30px] border border-white/10 bg-[rgba(7,9,12,0.58)] p-4 backdrop-blur-2xl">
                <p className="text-[11px] uppercase tracking-[0.28em] text-[--accent-orange]">
                  Легенда
                </p>
                <div className="mt-4 grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2 rounded-[22px] border border-white/10 bg-white/[0.04] p-4">
                    <div className="flex items-center gap-3">
                      <span className="h-3 w-3 rounded-full bg-[--accent-orange] shadow-[0_0_18px_rgba(255,132,56,0.8)]" />
                      <span className="text-sm text-white">Окуповане місто</span>
                    </div>
                    <p className="text-xs leading-5 text-[--muted]">
                      Помаранчева мітка тримає активний зв&apos;язок із містом, яке досі живе під
                      окупацією.
                    </p>
                  </div>

                  <div className="space-y-2 rounded-[22px] border border-white/10 bg-white/[0.04] p-4">
                    <div className="flex items-center gap-3">
                      <span className="h-3 w-3 rounded-full bg-white ring-2 ring-[rgba(218,59,59,0.8)]" />
                      <span className="text-sm text-white">Деокуповане місто</span>
                    </div>
                    <p className="text-xs leading-5 text-[--muted]">
                      Світла мітка з червоним контуром позначає місто, яке пережило окупацію.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <MapCanvas
              stories={stories}
              occupationOverlay={occupationOverlay}
              activeStory={activeStory}
              onPreviewStory={setActiveStory}
              onSelectStory={(story) => {
                setActiveStory(story);
                setSelectedStory(story);
              }}
            />
          </div>

          <aside className="relative bg-[linear-gradient(180deg,rgba(255,255,255,0.04),rgba(4,5,7,0.74))] p-4 backdrop-blur-2xl md:p-5 xl:max-h-[46rem] xl:overflow-y-auto 2xl:max-h-[50rem] story-scrollbar">
            <div className="flex items-end justify-between gap-4 border-b border-white/10 pb-4">
              <div className="space-y-2">
                <p className="text-[11px] uppercase tracking-[0.28em] text-[--muted]">
                  Опубліковані історії
                </p>
                <p className="max-w-[18rem] text-sm leading-6 text-white/78">
                  Тихий редакційний індекс: місто, дата, статус і прямий вхід у матеріал.
                </p>
              </div>
              <span className="text-[10px] uppercase tracking-[0.2em] text-[--muted]">
                {String(stories.length).padStart(2, "0")}
              </span>
            </div>

            {activeStory ? (
              <div className="mt-4 rounded-[28px] border border-white/10 bg-white/[0.04] p-4 xl:hidden">
                <p className="text-[11px] uppercase tracking-[0.28em] text-[--accent-orange]">
                  У фокусі
                </p>
                <p className="mt-3 font-display text-2xl leading-tight text-white">
                  {activeStory.title}
                </p>
                <p className="mt-2 text-sm leading-6 text-white/72">{activeStory.excerpt}</p>
              </div>
            ) : null}

            <div className="mt-4 space-y-1">
              {stories.length ? (
                stories.map((story, index) => {
                  const meta = occupationMeta[story.city.occupationStatus];
                  const active = activeStory?.id === story.id;

                  return (
                    <button
                      key={story.id}
                      type="button"
                      onMouseEnter={() => setActiveStory(story)}
                      onFocus={() => setActiveStory(story)}
                      onClick={() => {
                        setActiveStory(story);
                        setSelectedStory(story);
                      }}
                      className={`group relative block w-full overflow-hidden border-l py-4 pl-5 pr-3 text-left transition ${
                        active
                          ? "border-[--accent-orange] bg-[linear-gradient(90deg,rgba(255,132,56,0.16),rgba(255,132,56,0.03)_48%,transparent)]"
                          : "border-white/10 hover:border-white/30 hover:bg-white/[0.04]"
                      }`}
                    >
                      <div className="flex items-start gap-4">
                        <span className="pt-1 text-[10px] uppercase tracking-[0.22em] text-[--muted]">
                          {String(index + 1).padStart(2, "0")}
                        </span>

                        <div className="min-w-0 flex-1">
                          <p className="text-base leading-6 text-white">{story.title}</p>
                          <p className="mt-1 text-[11px] uppercase tracking-[0.18em] text-[--muted]">
                            {story.city.name} • {story.city.oblast}
                          </p>
                          <p className="text-clamp-3 mt-2 text-sm leading-6 text-white/64">
                            {story.excerpt}
                          </p>
                          <p className="mt-2 text-[11px] uppercase tracking-[0.16em] text-[--muted]">
                            {meta.label} • {story.publishedAt ? formatDate(story.publishedAt) : "Без дати"}
                          </p>
                        </div>

                        <span
                          className={`mt-2 h-2.5 w-2.5 shrink-0 rounded-full ${
                            story.city.occupationStatus === "occupied"
                              ? "bg-[--accent-orange]"
                              : "bg-white ring-2 ring-[rgba(218,59,59,0.8)]"
                          }`}
                        />
                      </div>
                    </button>
                  );
                })
              ) : (
                <div className="rounded-[26px] border border-dashed border-white/12 bg-white/[0.03] p-5 text-sm leading-6 text-[--muted]">
                  Після першої публікації тут з&apos;являться мітки і редакційний індекс історій.
                </div>
              )}
            </div>
          </aside>
        </div>
      </div>

      {selectedStory ? (
        <div className="story-fade-in fixed inset-0 z-40 flex items-end justify-center bg-[rgba(3,4,6,0.76)] p-4 backdrop-blur-sm md:items-center">
          <div className="glass-panel max-h-[90vh] w-full max-w-5xl overflow-hidden rounded-[34px]">
            <StorySheet story={selectedStory} onClose={() => setSelectedStory(null)} compact />
          </div>
        </div>
      ) : null}
    </>
  );
}
