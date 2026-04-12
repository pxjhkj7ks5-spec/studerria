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
    saved?: string;
  }>;
};

export default async function AdminStoriesPage({
  params,
  searchParams,
}: AdminStoriesPageProps) {
  const { adminPath } = await params;
  const { saved } = await searchParams;
  const stories = await getAdminStories();

  return (
    <section className="space-y-5">
      {saved ? (
        <div className="rounded-[24px] border border-[--accent-orange]/25 bg-[rgba(255,132,56,0.08)] px-5 py-4 text-sm text-[#f7d8c2]">
          Історію збережено. Якщо вона опублікована, мітка вже доступна на публічній карті.
        </div>
      ) : null}

      <div className="overflow-hidden rounded-[32px] border border-white/8 bg-white/[0.03]">
        <div className="grid grid-cols-[1.5fr_1fr_0.8fr_0.8fr] gap-4 border-b border-white/8 px-5 py-4 text-xs uppercase tracking-[0.24em] text-[--muted]">
          <span>Історія</span>
          <span>Місто</span>
          <span>Статус</span>
          <span>Оновлено</span>
        </div>

        {stories.length ? (
          stories.map((story) => (
            <Link
              key={story.id}
              href={`/${adminPath}/stories/${story.id}`}
              className="grid grid-cols-[1.5fr_1fr_0.8fr_0.8fr] gap-4 border-b border-white/6 px-5 py-5 transition hover:bg-white/[0.04]"
            >
              <div className="min-w-0">
                <p className="truncate font-semibold text-white">{story.title}</p>
                <p className="mt-1 text-sm text-[--muted]">{story.excerpt}</p>
              </div>
              <div className="min-w-0">
                <p className="truncate text-white">{story.city.name}</p>
                <p className="mt-1 text-sm text-[--muted]">{story.city.oblast}</p>
              </div>
              <div>
                <p className="text-white">{publicationMeta[story.publicationStatus]}</p>
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
