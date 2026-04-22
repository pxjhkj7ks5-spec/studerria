import Link from "next/link";
import { ChangelogButton } from "@/components/site/changelog-button";
import { getChangelog, getVersionInfo } from "@/lib/site-content";

const INSTAGRAM_URL = "https://www.instagram.com/charredmap?igsh=aTkxajBhZmt4M3Bt";

function InstagramIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      className="h-[1.05rem] w-[1.05rem]"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="3.25" y="3.25" width="17.5" height="17.5" rx="5.25" />
      <circle cx="12" cy="12" r="4.1" />
      <circle cx="17.35" cy="6.65" r="0.9" fill="currentColor" stroke="none" />
    </svg>
  );
}

export async function SiteFooter() {
  const [versionInfo, changelog] = await Promise.all([getVersionInfo(), getChangelog()]);

  return (
    <footer className="relative border-t border-white/8 px-4 py-5">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-[linear-gradient(90deg,transparent,rgba(255,132,56,0.5),transparent)]" />
      <div className="mx-auto flex w-full max-w-[1720px] flex-col gap-4 text-sm text-[--muted] md:flex-row md:items-end md:justify-between">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-3 text-[11px] uppercase tracking-[0.3em]">
            <span className="text-[--accent-orange]">charredmap</span>
            <span className="h-px w-8 bg-white/12" />
            <span>Історії міст України</span>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <span className="font-display text-xl text-white">charredmap</span>
            <span className="text-white/70">v{versionInfo.version}</span>
          </div>
          <p className="max-w-2xl leading-6">
            Тут зібрані опубліковані історії, а через окрему форму можна надіслати новий
            матеріал.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <a
            href={INSTAGRAM_URL}
            target="_blank"
            rel="noreferrer"
            aria-label="Instagram charredmap"
            className="group inline-flex items-center gap-2 rounded-full border border-white/10 bg-[linear-gradient(135deg,rgba(255,132,56,0.14),rgba(255,255,255,0.05))] px-4 py-2 text-sm text-white transition hover:border-[--accent-orange]/50 hover:bg-[linear-gradient(135deg,rgba(255,132,56,0.22),rgba(255,255,255,0.08))] hover:shadow-[0_10px_30px_rgba(255,132,56,0.16)]"
          >
            <span className="flex h-8 w-8 items-center justify-center rounded-full border border-white/10 bg-black/25 text-[--accent-orange] transition group-hover:border-[--accent-orange]/30 group-hover:bg-black/35">
              <InstagramIcon />
            </span>
            <span className="font-medium tracking-[0.02em]">Instagram</span>
          </a>
          <Link
            href="/submit"
            className="rounded-full border border-white/10 bg-white/[0.04] px-4 py-2 text-sm text-white transition hover:border-[--accent-orange]/40 hover:bg-[rgba(255,132,56,0.08)]"
          >
            Надіслати історію
          </Link>
          <ChangelogButton
            version={changelog.version}
            generatedAt={changelog.generatedAt}
            entries={changelog.entries}
          />
        </div>
      </div>
    </footer>
  );
}
