import Link from "next/link";
import { withBasePath } from "@/lib/base-path";
import { occupationMeta } from "@/lib/constants";
import type { SerializedStory } from "@/lib/data";
import { formatDate } from "@/lib/utils";
import { StoryBody } from "@/components/story/story-body";

type StorySheetProps = {
  story: SerializedStory;
  onClose?: () => void;
  compact?: boolean;
};

export function StorySheet({ story, onClose, compact = false }: StorySheetProps) {
  const occupation = occupationMeta[story.city.occupationStatus];

  return (
    <article className="relative flex h-full min-h-0 flex-col overflow-hidden rounded-[32px] bg-[linear-gradient(180deg,rgba(255,255,255,0.06),rgba(5,6,8,0.92))] text-white">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(255,132,56,0.18),_transparent_26%),radial-gradient(circle_at_82%_12%,_rgba(255,255,255,0.08),_transparent_18%)]" />

      <div className="relative overflow-hidden border-b border-white/10">
        {story.coverImageUrl ? (
          <img
            src={withBasePath(story.coverImageUrl)}
            alt={story.title}
            className="h-64 w-full object-cover md:h-[21rem]"
          />
        ) : (
          <div className="flex h-64 items-end bg-[radial-gradient(circle_at_top_left,_rgba(255,132,56,0.55),_transparent_34%),linear-gradient(145deg,#101113,#050505)] p-6 md:h-[21rem]">
            <div className="max-w-lg space-y-3">
              <p className="text-xs uppercase tracking-[0.3em] text-[--accent-orange]">
                {occupation.label}
              </p>
              <p className="font-display text-3xl leading-tight md:text-5xl">
                {story.city.name}
              </p>
            </div>
          </div>
        )}

        <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(5,6,8,0.18),rgba(5,6,8,0.56)_48%,rgba(5,6,8,0.94)_100%)]" />

        <div className="absolute inset-x-0 top-0 flex items-start justify-between p-4 md:p-6">
          <div className="rounded-full border border-white/12 bg-black/40 px-3 py-1 text-[10px] uppercase tracking-[0.22em] text-[--paper] backdrop-blur-xl">
            {occupation.badge}
          </div>
          {onClose ? (
            <button
              type="button"
              onClick={onClose}
              aria-label="Закрити історію"
              className="rounded-full border border-white/12 bg-black/30 px-3 py-1 text-xs text-[--muted] transition hover:border-white/30 hover:text-white"
            >
              Закрити
            </button>
          ) : null}
        </div>

        <div className="absolute inset-x-0 bottom-0 p-5 md:p-8">
          <div className="max-w-3xl space-y-4">
            <div className="flex flex-wrap gap-2 text-[11px] uppercase tracking-[0.22em] text-[#e8ddd4]/78">
              <span className="rounded-full border border-white/10 bg-black/30 px-3 py-1 backdrop-blur-xl">
                {story.city.name}
              </span>
              <span className="rounded-full border border-white/10 bg-black/30 px-3 py-1 backdrop-blur-xl">
                {story.city.oblast}
              </span>
              {story.publishedAt ? (
                <span className="rounded-full border border-white/10 bg-black/30 px-3 py-1 backdrop-blur-xl">
                  {formatDate(story.publishedAt)}
                </span>
              ) : null}
            </div>

            <h1 className="font-display max-w-4xl text-3xl leading-[0.94] text-white md:text-5xl xl:text-6xl">
              {story.title}
            </h1>
            <p className="max-w-2xl text-sm leading-6 text-[#dcdde2] md:text-base">
              {story.excerpt}
            </p>
          </div>
        </div>
      </div>

      <div className={`relative story-scrollbar min-h-0 flex-1 overflow-y-auto overscroll-contain ${compact ? "p-5 md:p-6" : "p-6 md:p-8"}`}>
        <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_260px]">
          <div className="min-w-0 space-y-6">
            <StoryBody body={story.body} />
          </div>

          <aside className="flex flex-col gap-6 border-t border-white/10 pt-5 text-sm text-[--muted] lg:border-t-0 lg:border-l lg:pl-6 lg:pt-0">
            <div className="space-y-3">
              <p className="text-[11px] uppercase tracking-[0.28em] text-[--accent-orange]">
                Контекст
              </p>
              <div className="space-y-3">
                <div className="border-b border-white/10 pb-3">
                  <p className="text-[10px] uppercase tracking-[0.22em] text-[--muted]">
                    Місто
                  </p>
                  <p className="mt-1 text-base text-white">{story.city.name}</p>
                </div>
                <div className="border-b border-white/10 pb-3">
                  <p className="text-[10px] uppercase tracking-[0.22em] text-[--muted]">
                    Область
                  </p>
                  <p className="mt-1 text-base text-white">{story.city.oblast}</p>
                </div>
                <div className="border-b border-white/10 pb-3">
                  <p className="text-[10px] uppercase tracking-[0.22em] text-[--muted]">
                    Статус
                  </p>
                  <p className="mt-1 text-base text-white">{occupation.label}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-[0.22em] text-[--muted]">
                    Публікація
                  </p>
                  <p className="mt-1 text-base text-white">
                    {story.publishedAt ? formatDate(story.publishedAt) : "Без дати"}
                  </p>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <p className="text-[11px] uppercase tracking-[0.28em] text-[--accent-orange]">
                Перегляд
              </p>
              <p className="leading-6">
                Мітка прив&apos;язана до міста {story.city.name}. Окрема сторінка зберігає той самий
                матеріал, що відкривається з мапи.
              </p>
            </div>

            <div className="flex flex-col gap-3 pt-2">
              <Link
                href={`/stories/${story.slug}`}
                className="rounded-full bg-[--paper] px-4 py-2.5 text-center text-sm font-semibold text-black transition hover:bg-white"
              >
                Окрема сторінка
              </Link>
              <Link
                href="/"
                className="rounded-full border border-white/14 px-4 py-2.5 text-center text-sm text-[--muted] transition hover:border-white/30 hover:text-white"
              >
                Повернутись до мапи
              </Link>
              {onClose ? (
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded-full border border-white/10 px-4 py-2.5 text-sm text-[--muted] transition hover:border-white/30 hover:text-white"
                >
                  Закрити історію
                </button>
              ) : null}
            </div>
          </aside>
        </div>
      </div>
    </article>
  );
}
