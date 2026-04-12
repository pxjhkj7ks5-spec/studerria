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
    <article className="flex h-full flex-col overflow-hidden rounded-[28px] bg-[linear-gradient(180deg,rgba(255,255,255,0.08),rgba(10,10,10,0.82))] text-white">
      <div className="relative overflow-hidden border-b border-white/10">
        {story.coverImageUrl ? (
          <img
            src={withBasePath(story.coverImageUrl)}
            alt={story.title}
            className="h-56 w-full object-cover md:h-72"
          />
        ) : (
          <div className="flex h-56 items-end bg-[radial-gradient(circle_at_top_left,_rgba(255,132,56,0.55),_transparent_34%),linear-gradient(145deg,#101113,#050505)] p-6 md:h-72">
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

        <div className="absolute inset-x-0 top-0 flex items-start justify-between p-4 md:p-5">
          <div className="rounded-full border border-white/12 bg-black/40 px-3 py-1 text-[10px] uppercase tracking-[0.22em] text-[--paper] backdrop-blur-xl">
            {occupation.badge}
          </div>
          {onClose ? (
            <button
              type="button"
              onClick={onClose}
              className="rounded-full border border-white/12 bg-black/30 px-3 py-1 text-xs text-[--muted] transition hover:border-white/30 hover:text-white"
            >
              Закрити
            </button>
          ) : null}
        </div>
      </div>

      <div className={`story-scrollbar flex-1 overflow-y-auto ${compact ? "p-5" : "p-6 md:p-8"}`}>
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-3 text-xs uppercase tracking-[0.22em] text-[--muted]">
            <span>{story.city.name}</span>
            <span>{story.city.oblast}</span>
            {story.publishedAt ? <span>{formatDate(story.publishedAt)}</span> : null}
          </div>

          <div className="space-y-4">
            <h1 className="font-display text-3xl leading-tight md:text-5xl">{story.title}</h1>
            <p className="max-w-2xl text-sm leading-6 text-[--muted] md:text-base">
              Мітка прив&apos;язана до міста {story.city.name}. Публічна сторінка доступна окремо й зберігає той самий матеріал, що відкривається з мапи.
            </p>
          </div>

          <StoryBody body={story.body} />

          <div className="flex flex-wrap items-center gap-3 border-t border-white/10 pt-5">
            <Link
              href={`/stories/${story.slug}`}
              className="rounded-full bg-[--paper] px-4 py-2 text-sm font-semibold text-black transition hover:bg-white"
            >
              Окрема сторінка
            </Link>
            <Link
              href="/"
              className="rounded-full border border-white/14 px-4 py-2 text-sm text-[--muted] transition hover:border-white/30 hover:text-white"
            >
              Повернутись до мапи
            </Link>
          </div>
        </div>
      </div>
    </article>
  );
}
