import { ReviewStatus } from "@prisma/client";
import { notFound } from "next/navigation";
import { assertAdminPath, getAdminRoute, requireAdminSession } from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";
import { getAdminReviews } from "@/lib/data";

export const dynamic = "force-dynamic";

const reviewStatusLabels: Record<ReviewStatus, string> = {
  pending: "Очікує модерації",
  approved: "Опубліковано",
  rejected: "Приховано",
};

export default async function AdminReviewsPage({ params, searchParams }: {
  params: Promise<{ adminPath: string }>;
  searchParams: Promise<{ status?: string; ok?: string; error?: string }>;
}) {
  await requireAdminSession();
  const [{ adminPath }, query] = await Promise.all([params, searchParams]);
  assertAdminPath(adminPath);
  const status = query.status && Object.values(ReviewStatus).includes(query.status as ReviewStatus)
    ? query.status as ReviewStatus : undefined;
  if (query.status && !status) notFound();
  const reviews = await getAdminReviews(status);
  const base = `${getAdminRoute()}/reviews`;
  return (
    <main className="mx-auto w-full max-w-[1200px] px-4 py-6 md:px-6 md:py-8">
      <a className="text-sm text-[--muted]" href={withBasePath(getAdminRoute())}>Повернутися до огляду</a>
      <h1 className="mt-4 font-display text-5xl tracking-[-0.06em] text-white">Відгуки</h1>
      <p className="mt-3 text-sm text-[--muted]">Нові відгуки не публікуються без схвалення.</p>
      {query.ok ? <div className="status-message status-message--ok mt-5">{query.ok}</div> : null}
      {query.error ? <div className="status-message status-message--error mt-5">{query.error}</div> : null}
      <nav className="mt-6 flex flex-wrap gap-2">
        <a className={!status ? "accent-pill" : "ghost-pill"} href={withBasePath(base)}>Усі</a>
        {Object.values(ReviewStatus).map((item) => <a key={item} className={status === item ? "accent-pill" : "ghost-pill"} href={withBasePath(`${base}?status=${item}`)}>{reviewStatusLabels[item]}</a>)}
      </nav>
      <section className="glass-panel mt-6 grid gap-3 rounded-[2rem] p-6">
        {reviews.length ? reviews.map((review) => (
          <a className="grid gap-2 rounded-[1.35rem] border border-white/10 bg-white/[0.03] p-4 transition hover:border-white/20" href={withBasePath(`${base}/${review.id}`)} key={review.id}>
            <span className="flex flex-wrap justify-between gap-3"><strong className="text-white">{review.isAnonymous || !review.displayName ? "Анонімно" : review.displayName}</strong><span className="text-sm text-[--accent]">{reviewStatusLabels[review.status]}</span></span>
            <span className="line-clamp-2 text-sm text-[--muted]">{review.body}</span>
            <small className="text-[--muted]">{review.images.length} фото · {new Intl.DateTimeFormat("uk-UA", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Kyiv" }).format(review.createdAt)}</small>
          </a>
        )) : <p className="text-sm text-[--muted]">Відгуків за цим фільтром немає.</p>}
      </section>
    </main>
  );
}
