import Image from "next/image";
import type { Metadata } from "next";
import { PublicFrame } from "@/components/site/public-frame";
import { ReviewForm } from "@/components/site/review-form";
import { StructuredData } from "@/components/site/structured-data";
import { getApprovedReviews, getReviewOrderContext, getSiteSettings } from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import { siteName } from "@/lib/constants";
import { absoluteSiteUrl } from "@/lib/site-url";

export const dynamic = "force-dynamic";

const description = "Опубліковані відгуки клієнтів про YKG та форма для надсилання власного відгуку з фото.";
export const metadata: Metadata = {
  title: "Відгуки",
  description,
  alternates: { canonical: absoluteSiteUrl("/reviews") },
  openGraph: { type: "website", locale: "uk_UA", url: absoluteSiteUrl("/reviews"), siteName, title: `Відгуки | ${siteName}`, description },
  twitter: { card: "summary", title: `Відгуки | ${siteName}`, description },
};

function reviewDate(value: Date) {
  return new Intl.DateTimeFormat("uk-UA", { dateStyle: "long", timeZone: "Europe/Kyiv" }).format(value);
}

export default async function ReviewsPage({
  searchParams,
}: {
  searchParams: Promise<{ order?: string }>;
}) {
  const query = await searchParams;
  const [settings, reviews, reviewOrder] = await Promise.all([
    getSiteSettings(),
    getApprovedReviews(),
    query.order ? getReviewOrderContext(query.order) : null,
  ]);
  return (
    <PublicFrame telegramUrl={settings.telegramUrl}>
      <StructuredData data={{
        "@context": "https://schema.org",
        "@type": "BreadcrumbList",
        itemListElement: [
          { "@type": "ListItem", position: 1, name: siteName, item: absoluteSiteUrl() },
          { "@type": "ListItem", position: 2, name: "Відгуки", item: absoluteSiteUrl("/reviews") },
        ],
      }} />
      <main>
        <section className="site-section review-hero">
          <div className="site-container section-heading">
            <p className="eyebrow">Реальний досвід</p>
            <h1>Відгуки про YKG</h1>
            <p>Нові відгуки з’являються тут одразу. Власник може приховати відгук після перевірки, а позначку підтвердженої покупки додаємо лише за перевіреними даними.</p>
          </div>
        </section>

        <section className="site-container reviews-layout">
          <div className="reviews-list">
            {reviews.length > 0 ? reviews.map((review) => (
              <article className="review-card" key={review.id}>
                <header>
                  <div>
                    <strong>{review.isAnonymous || !review.displayName ? "Анонімно" : review.displayName}</strong>
                    {review.verifiedPurchase ? <span className="review-verified">Підтверджене замовлення</span> : null}
                  </div>
                  <time dateTime={review.createdAt.toISOString()}>{reviewDate(review.createdAt)}</time>
                </header>
                <p>{review.body}</p>
                {review.images.length > 0 ? (
                  <div className="review-card__images">
                    {review.images.map((image) => (
                      <a href={withBasePath(image.urlPath)} target="_blank" rel="noreferrer" key={image.id}>
                        <Image src={withBasePath(image.urlPath)} alt={image.alt} width={520} height={520} unoptimized />
                      </a>
                    ))}
                  </div>
                ) : null}
              </article>
            )) : (
              <div className="empty-catalog">
                <div><p className="eyebrow">Перші враження</p><h2>Схвалених відгуків поки немає</h2><p>Можливо, саме ваш досвід стане першим у цьому розділі.</p></div>
              </div>
            )}
          </div>
          <ReviewForm
            orderContext={reviewOrder ? {
              publicId: reviewOrder.publicId,
              number: reviewOrder.publicId.slice(0, 8).toUpperCase(),
              alreadySubmitted: Boolean(reviewOrder.review),
            } : null}
            invalidOrderLink={Boolean(query.order && !reviewOrder)}
          />
        </section>
      </main>
    </PublicFrame>
  );
}
