import { ChangelogButton } from "@/components/site/changelog-button";
import { getChangelog, getVersionInfo } from "@/lib/site-content";

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
            <span>Нічна редакційна мапа історій з міст України</span>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <span className="font-display text-xl text-white">charredmap</span>
            <span className="text-white/70">v{versionInfo.version}</span>
          </div>
          <p className="max-w-2xl leading-6">
            Публічний шар лишається камерним: одна мапа, один індекс матеріалів і changelog у
            футері без зайвого службового шуму.
          </p>
        </div>

        <div className="flex items-center gap-3">
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
