"use client";

import { useEffect, useState } from "react";
import { formatDate } from "@/lib/utils";
import type { ChangelogEntry } from "@/lib/site-content";

type ChangelogButtonProps = {
  version: string;
  generatedAt: string;
  entries: ChangelogEntry[];
};

export function ChangelogButton({
  version,
  generatedAt,
  entries,
}: ChangelogButtonProps) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open) {
      return;
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    };

    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = "";
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm text-white transition hover:border-[--accent-orange]/60 hover:bg-white/10"
      >
        Changelog
      </button>

      {open ? (
        <div className="story-fade-in fixed inset-0 z-50 flex items-end justify-center bg-black/65 p-4 md:items-center">
          <div className="glass-panel story-scrollbar max-h-[88vh] w-full max-w-3xl overflow-y-auto rounded-[30px] p-6 md:p-8">
            <div className="flex items-start justify-between gap-6">
              <div className="space-y-2">
                <p className="text-xs uppercase tracking-[0.28em] text-[--accent-orange]">
                  Історія змін
                </p>
                <h2 className="font-display text-3xl text-white md:text-4xl">
                  charredmap v{version}
                </h2>
                <p className="max-w-xl text-sm text-[--muted]">
                  JSON формується з git-комітів. Останнє оновлення: {formatDate(generatedAt)}.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="rounded-full border border-white/10 px-3 py-1 text-sm text-[--muted] transition hover:border-white/30 hover:text-white"
              >
                Закрити
              </button>
            </div>

            <div className="mt-8 space-y-4">
              {entries.length ? (
                entries.map((entry) => (
                  <div
                    key={entry.hash}
                    className="rounded-[24px] border border-white/8 bg-white/[0.035] p-4"
                  >
                    <div className="flex flex-wrap items-center gap-3 text-xs uppercase tracking-[0.18em] text-[--muted]">
                      <span>{entry.shortHash}</span>
                      <span>{formatDate(entry.date)}</span>
                    </div>
                    <p className="mt-3 text-base text-white">{entry.message}</p>
                  </div>
                ))
              ) : (
                <div className="rounded-[24px] border border-dashed border-white/12 bg-white/[0.03] p-6 text-sm text-[--muted]">
                  Поки що changelog порожній.
                </div>
              )}
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
