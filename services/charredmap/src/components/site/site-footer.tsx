import { ChangelogButton } from "@/components/site/changelog-button";
import { getChangelog, getVersionInfo } from "@/lib/site-content";

export async function SiteFooter() {
  const [versionInfo, changelog] = await Promise.all([getVersionInfo(), getChangelog()]);

  return (
    <footer className="border-t border-white/6 bg-black/45 px-4 py-4 backdrop-blur-xl">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-3 text-sm text-[--muted] md:flex-row md:items-center md:justify-between">
        <div className="flex flex-col gap-1 md:flex-row md:items-center md:gap-4">
          <span className="font-display text-lg text-white">charredmap</span>
          <span>Нічна редакційна мапа історій з міст України.</span>
          <span className="text-white/70">v{versionInfo.version}</span>
        </div>
        <ChangelogButton
          version={changelog.version}
          generatedAt={changelog.generatedAt}
          entries={changelog.entries}
        />
      </div>
    </footer>
  );
}
