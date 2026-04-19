import Link from "next/link";
import { setStoryPublicationStatusAction } from "@/app/actions/admin";
import { SubmitButton } from "@/components/admin/submit-button";
import { publicationMeta } from "@/lib/constants";
import { getAdminStories } from "@/lib/data";
import { formatDate } from "@/lib/utils";

export const dynamic = "force-dynamic";

type AdminStoriesPageProps = {
  params: Promise<{
    adminPath: string;
  }>;
  searchParams: Promise<{
    deleted?: string;
    saved?: string;
  }>;
};

function getStatusBadgeClassName(status: keyof typeof publicationMeta) {
  switch (status) {
    case "published":
      return "border border-[--accent-orange]/30 bg-[rgba(255,132,56,0.14)] text-[--accent-ember]";
    case "submitted":
      return "border border-white/12 bg-white/[0.06] text-white";
    case "draft":
    default:
      return "border border-white/10 bg-black/25 text-[--muted]";
  }
}

export default async function AdminStoriesPage({
  params,
  searchParams,
}: AdminStoriesPageProps) {
  const { adminPath } = await params;
  const { deleted, saved } = await searchParams;
  const stories = await getAdminStories();
  const groupedStories = [
    {
      key: "submitted",
      title: "На модерації",
      stories: stories.filter((story) => story.publicationStatus === "submitted"),
      tone: "accent",
    },
    {
      key: "draft",
      title: "Чернетки",
      stories: stories.filter((story) => story.publicationStatus === "draft"),
      tone: "muted",
    },
    {
      key: "published",
      title: "Опубліковані",
      stories: stories.filter((story) => story.publicationStatus === "published"),
      tone: "muted",
    },
  ] as const;

  return (
    <section className="space-y-6">
      {saved === "1" ? (
        <div className="rounded-[24px] border border-[--accent-orange]/25 bg-[rgba(255,132,56,0.08)] px-5 py-4 text-sm text-[#f7d8c2]">
          Зміни збережено.
        </div>
      ) : null}

      {saved === "0" ? (
        <div className="rounded-[24px] border border-[--accent-red]/28 bg-[rgba(218,59,59,0.12)] px-5 py-4 text-sm text-[#ffd2d2]">
          Не вдалося змінити статус історії.
        </div>
      ) : null}

      {deleted === "1" ? (
        <div className="rounded-[24px] border border-[--accent-red]/28 bg-[rgba(218,59,59,0.12)] px-5 py-4 text-sm text-[#ffd2d2]">
          Історію видалено.
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        {groupedStories.map((group) => (
          <div key={group.key} className="glass-panel rounded-[24px] p-5">
            <p
              className={`text-xs uppercase tracking-[0.24em] ${
                group.tone === "accent" ? "text-[--accent-orange]" : "text-[--muted]"
              }`}
            >
              {group.title}
            </p>
            <p className="mt-2 font-display text-4xl text-white">
              {String(group.stories.length).padStart(2, "0")}
            </p>
          </div>
        ))}
      </div>

      {stories.length ? (
        groupedStories.map((group) =>
          group.stories.length ? (
            <div key={group.key} className="glass-panel overflow-hidden rounded-[28px]">
              <div className="border-b border-white/8 px-5 py-4">
                <h2
                  className={`text-sm uppercase tracking-[0.24em] ${
                    group.tone === "accent" ? "text-[--accent-orange]" : "text-[--muted]"
                  }`}
                >
                  {group.title}
                </h2>
              </div>

              <div className="divide-y divide-white/8">
                {group.stories.map((story) => (
                  <article key={story.id} className="px-5 py-5">
                    <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                      <div className="min-w-0 space-y-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`inline-flex rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.18em] ${getStatusBadgeClassName(
                              story.publicationStatus,
                            )}`}
                          >
                            {publicationMeta[story.publicationStatus]}
                          </span>
                          <span className="text-[11px] uppercase tracking-[0.18em] text-[--muted]">
                            {story.city.name} • {story.city.oblast}
                          </span>
                        </div>

                        <h3 className="font-display text-2xl leading-tight text-white">
                          {story.title}
                        </h3>
                        <p className="max-w-3xl text-sm leading-6 text-white/68">
                          {story.excerpt}
                        </p>
                        <p className="text-[11px] uppercase tracking-[0.16em] text-[--muted]">
                          Оновлено {formatDate(story.updatedAt)}
                          {story.submitterName ? ` • ${story.submitterName}` : ""}
                        </p>
                      </div>

                      <div className="flex flex-wrap gap-2 xl:justify-end">
                        {story.publicationStatus !== "published" ? (
                          <form action={setStoryPublicationStatusAction}>
                            <input type="hidden" name="storyId" value={story.id} />
                            <input type="hidden" name="publicationStatus" value="published" />
                            <SubmitButton variant="accent" pendingLabel="Публікація...">
                              Опублікувати
                            </SubmitButton>
                          </form>
                        ) : (
                          <form action={setStoryPublicationStatusAction}>
                            <input type="hidden" name="storyId" value={story.id} />
                            <input type="hidden" name="publicationStatus" value="draft" />
                            <SubmitButton variant="secondary" pendingLabel="Оновлення...">
                              У чернетку
                            </SubmitButton>
                          </form>
                        )}

                        {story.publicationStatus === "submitted" ? (
                          <form action={setStoryPublicationStatusAction}>
                            <input type="hidden" name="storyId" value={story.id} />
                            <input type="hidden" name="publicationStatus" value="draft" />
                            <SubmitButton variant="secondary" pendingLabel="Оновлення...">
                              У чернетку
                            </SubmitButton>
                          </form>
                        ) : null}

                        <Link
                          href={`/${adminPath}/stories/${story.id}`}
                          className="rounded-full border border-white/12 px-5 py-3 text-sm text-white transition hover:border-white/30"
                        >
                          Редагувати
                        </Link>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            </div>
          ) : null,
        )
      ) : (
        <div className="rounded-[28px] border border-dashed border-white/12 bg-white/[0.03] px-5 py-12 text-center text-sm text-[--muted]">
          Історій поки немає.
        </div>
      )}
    </section>
  );
}
