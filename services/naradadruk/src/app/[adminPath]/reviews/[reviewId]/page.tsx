import Image from "next/image";
import { ReviewStatus } from "@prisma/client";
import { notFound } from "next/navigation";
import { deleteReviewAction, moderateReviewAction } from "@/app/actions/admin";
import { assertAdminPath, getAdminRoute, requireAdminSession } from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";
import { getAdminReview } from "@/lib/data";

export const dynamic = "force-dynamic";

const reviewStatusLabels: Record<ReviewStatus, string> = { pending: "Очікує модерації", approved: "Опубліковано", rejected: "Приховано" };

export default async function AdminReviewPage({ params, searchParams }: {
  params: Promise<{ adminPath: string; reviewId: string }>;
  searchParams: Promise<{ ok?: string; error?: string }>;
}) {
  await requireAdminSession();
  const [{ adminPath, reviewId }, query] = await Promise.all([params, searchParams]);
  assertAdminPath(adminPath);
  const id = Number(reviewId);
  if (!Number.isInteger(id) || id <= 0) notFound();
  const review = await getAdminReview(id);
  if (!review) notFound();
  return (
    <main className="mx-auto w-full max-w-[1000px] px-4 py-6 md:px-6 md:py-8">
      <a className="text-sm text-[--muted]" href={withBasePath(`${getAdminRoute()}/reviews`)}>До списку відгуків</a>
      <div className="mt-4 flex flex-wrap items-start justify-between gap-4"><div><h1 className="font-display text-5xl tracking-[-0.06em] text-white">Відгук #{review.id}</h1><p className="mt-2 text-[--accent]">{reviewStatusLabels[review.status]}</p>{review.verifiedPurchase && review.order ? <a className="mt-3 inline-flex text-sm text-white/80 underline" href={withBasePath(`${getAdminRoute()}/orders/${review.order.publicId}`)}>Підтверджене замовлення #{review.order.publicId.slice(0, 8).toUpperCase()}</a> : null}</div><strong className="text-white">{review.isAnonymous || !review.displayName ? "Анонімно" : review.displayName}</strong></div>
      {query.ok ? <div className="status-message status-message--ok mt-5">{query.ok}</div> : null}
      {query.error ? <div className="status-message status-message--error mt-5">{query.error}</div> : null}
      <section className="glass-panel mt-6 rounded-[2rem] p-6">
        <p className="whitespace-pre-wrap text-white/90">{review.body}</p>
        {review.images.length ? <div className="mt-6 grid grid-cols-2 gap-3 md:grid-cols-4">{review.images.map((image) => <a href={withBasePath(image.urlPath)} target="_blank" rel="noreferrer" key={image.id}><Image className="aspect-square w-full rounded-2xl object-cover" src={withBasePath(image.urlPath)} alt={image.alt} width={500} height={500} unoptimized /></a>)}</div> : null}
        <div className="mt-6 flex flex-wrap gap-3">
          {review.status === ReviewStatus.pending || (review.status === ReviewStatus.approved && !review.moderatedAt) ? <form action={moderateReviewAction}><input type="hidden" name="reviewId" value={review.id} /><input type="hidden" name="status" value="approved" /><button className="accent-pill" type="submit">{review.status === ReviewStatus.pending ? "Опублікувати" : "Підтвердити"}</button></form> : null}
          {review.status !== ReviewStatus.rejected && !review.moderatedAt ? <form action={moderateReviewAction}><input type="hidden" name="reviewId" value={review.id} /><input type="hidden" name="status" value="rejected" /><button className="ghost-pill" type="submit">Приховати</button></form> : null}
          <form action={deleteReviewAction}><input type="hidden" name="reviewId" value={review.id} /><button className="ghost-pill" type="submit">Видалити назавжди</button></form>
        </div>
      </section>
    </main>
  );
}
