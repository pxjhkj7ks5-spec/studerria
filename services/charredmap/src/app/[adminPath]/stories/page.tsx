import Link from "next/link";
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
  const submittedStories = stories.filter((story) => story.publicationStatus === "submitted");
  const draftStories = stories.filter((story) => story.publicationStatus === "draft");
  const publishedStories = stories.filter((story) => story.publicationStatus === "published");

  return (
    <section className="space-y-6">
      {saved ? (
        <div className="rounded-[24px] border border-[--accent-orange]/25 bg-[rgba(255,132,56,0.08)] px-5 py-4 text-sm text-[#f7d8c2]">
          Історію збережено. Якщо вона опублікована, мітка вже доступна на публічній карті.
        </div>
      ) : null}

      {deleted === "1" ? (
        <div className="rounded-[24px] border border-[--accent-red]/28 bg-[rgba(218,59,59,0.12)] px-5 py-4 text-sm text-[#ffd2d2]">
          Історію видалено.
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <div className="glass-panel rounded-[28px] p-5">
          <p className="text-xs uppercase tracking-[0.24em] text-[--accent-orange]">
            На модерації
          </p>
          <p className="mt-3 font-display text-5xl leading-none text-white">
            {String(submittedStories.length).padStart(2, "0")}
          </p>
          <p className="mt-3 text-sm leading-6 text-white/70">
            Публічні подання, які ще не пройшли редакторське рішення.
          </p>
        </div>

        <div className="glass-panel rounded-[28px] p-5">
          <p className="text-xs uppercase tracking-[0.24em] text-[--muted]">Чернетки</p>
          <p className="mt-3 font-display text-5xl leading-none text-white">
            {String(draftStories.length).padStart(2, "0")}
          </p>
          <p className="mt-3 text-sm leading-6 text-white/70">
            Матеріали, які ще лишаються у внутрішній редакторській роботі.
          </p>
        </div>

        <div className="glass-panel rounded-[28px] p-5">
          <p className="text-xs uppercase tracking-[0.24em] text-[--muted]">Опубліковано</p>
          <p className="mt-3 font-display text-5xl leading-none text-white">
            {String(publishedStories.length).padStart(2, "0")}
          </p>
          <p className="mt-3 text-sm leading-6 text-white/70">
            Історії, які вже живуть на публічній карті.
          </p>
        </div>
      </div>

      {submittedStories.length ? (
        <div className="glass-panel overflow-hidden rounded-[32px]">
          <div className="flex flex-col gap-3 border-b border-white/8 px-5 py-5 md:flex-row md:items-end md:justify-between">
            <div className="space-y-2">
              <p className="text-xs uppercase tracking-[0.26em] text-[--accent-orange]">
                Черга модерації
              </p>
              <h2 className="font-display text-3xl text-white">Нові публічні подання</h2>
            </div>
            <p className="max-w-xl text-sm leading-6 text-white/70">
              Тут видно автора, контакт і місто ще до публікації. Один клік веде в повний редактор.
            </p>
          </div>

          <div className="grid gap-4 p-4 xl:grid-cols-2">
            {submittedStories.map((story) => (
              <Link
                key={story.id}
                href={`/${adminPath}/stories/${story.id}`}
                className="rounded-[28px] border border-white/10 bg-white/[0.04] p-5 transition hover:border-white/22 hover:bg-white/[0.06]"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0 space-y-2">
                    <p className="text-xs uppercase tracking-[0.22em] text-[--accent-orange]">
                      {story.city.name} • {story.city.oblast}
                    </p>
                    <h3 className="font-display text-2xl leading-tight text-white">
                      {story.title}
                    </h3>
                  </div>
                  <span
                    className={`shrink-0 rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.18em] ${getStatusBadgeClassName(
                      story.publicationStatus,
                    )}`}
                  >
                    {publicationMeta[story.publicationStatus]}
                  </span>
                </div>

                <p className="mt-4 text-sm leading-6 text-white/68">{story.excerpt}</p>

                <div className="mt-5 grid gap-4 border-t border-white/8 pt-4 md:grid-cols-2">
                  <div>
                    <p className="text-[10px] uppercase tracking-[0.18em] text-white/40">
                      Автор
                    </p>
                    <p className="mt-2 text-sm text-white">
                      {story.submitterName ?? "Не вказано"}
                    </p>
                  </div>
                  <div>
                    <p className="text-[10px] uppercase tracking-[0.18em] text-white/40">
                      Контакт
                    </p>
                    <p className="mt-2 break-words text-sm text-white/78">
                      {story.submitterContact ?? "Не вказано"}
                    </p>
                  </div>
                </div>

                <p className="mt-4 text-[11px] uppercase tracking-[0.18em] text-[--muted]">
                  Надіслано {formatDate(story.createdAt)} • Оновлено {formatDate(story.updatedAt)}
                </p>
              </Link>
            ))}
          </div>
        </div>
      ) : null}

      <div className="overflow-hidden rounded-[32px] border border-white/8 bg-white/[0.03]">
        <div className="grid grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,0.8fr)_minmax(0,0.9fr)] gap-4 border-b border-white/8 px-5 py-4 text-xs uppercase tracking-[0.24em] text-[--muted]">
          <span>Історія</span>
          <span>Місто / автор</span>
          <span>Статус</span>
          <span>Оновлено</span>
        </div>

        {stories.length ? (
          stories.map((story) => (
            <Link
              key={story.id}
              href={`/${adminPath}/stories/${story.id}`}
              className="grid grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)_minmax(0,0.8fr)_minmax(0,0.9fr)] gap-4 border-b border-white/6 px-5 py-5 transition hover:bg-white/[0.04]"
            >
              <div className="min-w-0">
                <p className="truncate font-semibold text-white">{story.title}</p>
                <p className="mt-1 text-sm text-[--muted]">{story.excerpt}</p>
              </div>
              <div className="min-w-0">
                <p className="truncate text-white">{story.city.name}</p>
                <p className="mt-1 text-sm text-[--muted]">
                  {story.submitterName ? `${story.city.oblast} • ${story.submitterName}` : story.city.oblast}
                </p>
              </div>
              <div>
                <span
                  className={`inline-flex rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.18em] ${getStatusBadgeClassName(
                    story.publicationStatus,
                  )}`}
                >
                  {publicationMeta[story.publicationStatus]}
                </span>
              </div>
              <div>
                <p className="text-white">{formatDate(story.updatedAt)}</p>
              </div>
            </Link>
          ))
        ) : (
          <div className="px-5 py-12 text-center text-sm text-[--muted]">
            Історій поки немає. Почніть з першої публікації.
          </div>
        )}
      </div>
    </section>
  );
}
