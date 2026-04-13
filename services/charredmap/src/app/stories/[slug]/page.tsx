import Link from "next/link";
import { notFound } from "next/navigation";
import { StoryBody } from "@/components/story/story-body";
import { withBasePath } from "@/lib/base-path";
import { occupationMeta } from "@/lib/constants";
import { getPublishedStoryBySlug } from "@/lib/data";
import { formatDate } from "@/lib/utils";

export const dynamic = "force-dynamic";

type StoryPageProps = {
  params: Promise<{
    slug: string;
  }>;
};

export default async function StoryPage({ params }: StoryPageProps) {
  const { slug } = await params;
  const story = await getPublishedStoryBySlug(slug);

  if (!story) {
    notFound();
  }
  const occupation = occupationMeta[story.city.occupationStatus];

  return (
    <main className="relative pb-20">
      <section className="relative isolate overflow-hidden border-b border-white/8">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(255,132,56,0.14),_transparent_28%),radial-gradient(circle_at_86%_12%,_rgba(255,255,255,0.06),_transparent_20%),linear-gradient(180deg,rgba(255,255,255,0.03),transparent_32%)]" />
        <div className="mx-auto grid w-full max-w-[1720px] gap-6 px-4 py-6 md:px-6 md:py-8 xl:grid-cols-[minmax(0,1.14fr)_380px] 2xl:grid-cols-[minmax(0,1.18fr)_420px] xl:items-end">
          <article className="glass-panel overflow-hidden rounded-[38px]">
            <div className="relative min-h-[28rem] md:min-h-[34rem] xl:min-h-[42rem] 2xl:min-h-[46rem]">
              {story.coverImageUrl ? (
                <img
                  src={withBasePath(story.coverImageUrl)}
                  alt={story.title}
                  className="absolute inset-0 h-full w-full object-cover"
                />
              ) : (
                <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(255,132,56,0.5),_transparent_32%),linear-gradient(145deg,#111318,#050607)]" />
              )}

              <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(5,6,8,0.18),rgba(5,6,8,0.4)_38%,rgba(5,6,8,0.96)_100%)]" />

              <div className="absolute inset-x-0 top-0 flex items-start justify-between gap-4 p-4 md:p-6">
                <Link
                  href="/"
                  className="rounded-full border border-white/12 bg-black/30 px-4 py-2 text-xs uppercase tracking-[0.22em] text-white/86 backdrop-blur-xl transition hover:border-white/24 hover:text-white"
                >
                  До мапи
                </Link>
                <div className="rounded-full border border-white/12 bg-black/36 px-3 py-1 text-[10px] uppercase tracking-[0.22em] text-[--paper] backdrop-blur-xl">
                  {occupation.badge}
                </div>
              </div>

              <div className="absolute inset-x-0 bottom-0 p-5 md:p-8 xl:p-10">
                <div className="max-w-4xl space-y-5">
                  <div className="flex flex-wrap gap-2 text-[11px] uppercase tracking-[0.2em] text-[#e8ddd4]/78">
                    <span className="rounded-full border border-white/10 bg-black/30 px-3 py-1 backdrop-blur-xl">
                      {story.city.name}
                    </span>
                    <span className="rounded-full border border-white/10 bg-black/30 px-3 py-1 backdrop-blur-xl">
                      {story.city.oblast}
                    </span>
                    <span className="rounded-full border border-white/10 bg-black/30 px-3 py-1 backdrop-blur-xl">
                      {story.publishedAt ? formatDate(story.publishedAt) : "Без дати"}
                    </span>
                  </div>

                  <h1 className="font-display max-w-5xl text-[clamp(2.7rem,6vw,6.4rem)] leading-[0.9] tracking-[-0.04em] text-white">
                    {story.title}
                  </h1>
                  <p className="max-w-3xl text-base leading-7 text-[#dde0e6] md:text-lg">
                    {story.excerpt}
                  </p>
                </div>
              </div>
            </div>
          </article>

          <aside className="xl:sticky xl:top-6">
            <div className="space-y-4">
              <div className="glass-panel rounded-[32px] p-5 md:p-6">
                <p className="text-[11px] uppercase tracking-[0.3em] text-[--accent-orange]">
                  Контекст історії
                </p>
                <div className="mt-5 space-y-4">
                  <div className="border-b border-white/10 pb-4">
                    <p className="text-[10px] uppercase tracking-[0.22em] text-[--muted]">
                      Місто
                    </p>
                    <p className="mt-1 text-xl text-white">{story.city.name}</p>
                  </div>
                  <div className="border-b border-white/10 pb-4">
                    <p className="text-[10px] uppercase tracking-[0.22em] text-[--muted]">
                      Область
                    </p>
                    <p className="mt-1 text-xl text-white">{story.city.oblast}</p>
                  </div>
                  <div className="border-b border-white/10 pb-4">
                    <p className="text-[10px] uppercase tracking-[0.22em] text-[--muted]">
                      Статус
                    </p>
                    <p className="mt-1 text-xl text-white">{occupation.label}</p>
                  </div>
                  <div>
                    <p className="text-[10px] uppercase tracking-[0.22em] text-[--muted]">
                      Публікація
                    </p>
                    <p className="mt-1 text-xl text-white">
                      {story.publishedAt ? formatDate(story.publishedAt) : "Без дати"}
                    </p>
                  </div>
                </div>
              </div>

              <div className="glass-panel rounded-[32px] p-5 md:p-6">
                <p className="text-[11px] uppercase tracking-[0.3em] text-[--accent-orange]">
                  Читання
                </p>
                <p className="mt-4 text-sm leading-7 text-white/74">
                  На desktop ця сторінка працює як окрема reading-surface: широкий hero зверху,
                  далі сконцентрований текстовий блок без модального відчуття.
                </p>
                <div className="mt-5 flex flex-col gap-3">
                  <a
                    href="#story-body"
                    className="rounded-full bg-[--paper] px-4 py-2.5 text-center text-sm font-semibold text-black transition hover:bg-white"
                  >
                    Перейти до тексту
                  </a>
                  <Link
                    href="/"
                    className="rounded-full border border-white/14 px-4 py-2.5 text-center text-sm text-[--muted] transition hover:border-white/30 hover:text-white"
                  >
                    Повернутись до мапи
                  </Link>
                </div>
              </div>
            </div>
          </aside>
        </div>
      </section>

      <section className="mx-auto w-full max-w-[1180px] px-4 py-10 md:px-6 md:py-14">
        <article id="story-body" className="glass-panel rounded-[36px] p-6 md:p-8 xl:p-10">
          <div className="max-w-3xl space-y-6">
            <p className="text-[11px] uppercase tracking-[0.3em] text-[--accent-orange]">
              Історія
            </p>
            <StoryBody body={story.body} />
          </div>
        </article>
      </section>
    </main>
  );
}
