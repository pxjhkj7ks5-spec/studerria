import Image from "next/image";
import { notFound } from "next/navigation";
import { getProductBySlug, getSiteSettings } from "@/lib/data";
import { withBasePath } from "@/lib/base-path";

export const dynamic = "force-dynamic";

type ProductPageProps = {
  params: Promise<{
    slug: string;
  }>;
};

export default async function ProductPage({ params }: ProductPageProps) {
  const { slug } = await params;
  const product = await getProductBySlug(slug);

  if (!product) {
    notFound();
  }

  const settings = await getSiteSettings();

  return (
    <main className="mx-auto w-full max-w-[1400px] px-4 py-8 md:px-6 md:py-10">
      <a
        className="reveal-up delay-1 text-sm text-[--muted] transition hover:text-white"
        href={withBasePath(`/category/${product.category.slug}`)}
      >
        До категорії {product.category.name}
      </a>

      <div className="mt-4 grid gap-6 lg:grid-cols-[1.05fr_0.95fr]">
        <section className="reveal-up delay-2 grid gap-4">
          <div className="interactive-card overflow-hidden rounded-[2rem] border border-white/10 bg-[--surface-strong]">
            {product.coverImage ? (
              <Image
                src={withBasePath(product.coverImage.urlPath)}
                alt={product.coverImage.alt || product.title}
                width={1400}
                height={1050}
                unoptimized
                className="aspect-[4/3] h-full w-full object-cover"
              />
            ) : (
              <div className="product-placeholder aspect-[4/3] h-full w-full">
                <span>{product.category.name}</span>
              </div>
            )}
          </div>

          {product.images.length > 1 ? (
            <div className="stagger-grid grid gap-3 sm:grid-cols-3">
              {product.images.map((image) => (
                <div key={image.id} className="interactive-card overflow-hidden rounded-[1.5rem] border border-white/10 bg-[--surface-strong]">
                  <Image
                    src={withBasePath(image.urlPath)}
                    alt={image.alt || product.title}
                    width={900}
                    height={675}
                    unoptimized
                    className="aspect-[4/3] h-full w-full object-cover"
                  />
                </div>
              ))}
            </div>
          ) : null}
        </section>

        <section className="flex flex-col gap-5">
          <div className="glass-panel reveal-up delay-2 rounded-[2rem] p-6 md:p-7">
            <div className="flex flex-wrap items-center justify-between gap-3 text-xs uppercase tracking-[0.24em] text-[--muted]">
              <span>{product.category.name}</span>
              <span>{product.status}</span>
            </div>

            <h1 className="mt-4 font-display text-5xl tracking-[-0.06em] text-white">{product.title}</h1>
            <p className="mt-4 text-base leading-8 text-[--muted]">{product.shortDescription}</p>

            <div className="mt-6 flex flex-wrap items-end justify-between gap-4">
              <div>
                <p className="text-sm text-[--muted]">Орієнтовна ціна</p>
                <p className="mt-1 font-display text-4xl tracking-[-0.05em] text-white">{product.priceLabel}</p>
              </div>

              <a className="accent-pill" href={product.telegramUrl} target="_blank" rel="noreferrer">
                Замовити
              </a>
            </div>
          </div>

          <div className="stagger-grid grid gap-4 md:grid-cols-2">
            <div className="glass-panel interactive-card rounded-[1.7rem] p-5">
              <p className="text-xs uppercase tracking-[0.24em] text-[--accent]">Матеріали</p>
              <p className="mt-3 text-sm leading-7 text-[--muted]">{product.materialNote || settings.materialsNote}</p>
            </div>
            <div className="glass-panel interactive-card rounded-[1.7rem] p-5">
              <p className="text-xs uppercase tracking-[0.24em] text-[--accent]">Термін</p>
              <p className="mt-3 text-sm leading-7 text-[--muted]">{product.leadTime || settings.leadTimeNote}</p>
            </div>
            <div className="glass-panel interactive-card rounded-[1.7rem] p-5">
              <p className="text-xs uppercase tracking-[0.24em] text-[--accent]">Доставка</p>
              <p className="mt-3 text-sm leading-7 text-[--muted]">{product.deliveryNote || settings.deliveryNote}</p>
            </div>
            <div className="glass-panel interactive-card rounded-[1.7rem] p-5">
              <p className="text-xs uppercase tracking-[0.24em] text-[--accent]">Оплата</p>
              <p className="mt-3 text-sm leading-7 text-[--muted]">{product.paymentNote || settings.paymentNote}</p>
            </div>
          </div>

          <div className="glass-panel reveal-up delay-3 rounded-[2rem] p-6">
            <h2 className="font-display text-3xl tracking-[-0.05em] text-white">Опис</h2>
            <p className="mt-4 whitespace-pre-line text-sm leading-7 text-[--muted]">{product.fullDescription}</p>
          </div>

          {product.variants.length > 0 ? (
            <div className="glass-panel reveal-up delay-4 rounded-[2rem] p-6">
              <h2 className="font-display text-3xl tracking-[-0.05em] text-white">Варіанти</h2>
              <div className="stagger-list mt-5 grid gap-3">
                {product.variants.map((variant) => (
                  <div
                    key={variant.id}
                    className="interactive-card flex flex-col gap-2 rounded-[1.25rem] border border-white/10 bg-white/[0.03] px-4 py-4 md:flex-row md:items-center md:justify-between"
                  >
                    <div>
                      <div className="font-medium text-white">{variant.label}</div>
                      {variant.description ? (
                        <p className="mt-1 text-sm leading-6 text-[--muted]">{variant.description}</p>
                      ) : null}
                    </div>
                    <div className="text-sm font-semibold text-white">{variant.price} грн</div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </section>
      </div>

      <div className="reveal-up delay-5 sticky bottom-4 z-20 mt-8 lg:hidden">
        <div className="glass-panel float-soft flex items-center justify-between gap-4 rounded-full px-4 py-3">
          <div>
            <p className="text-xs uppercase tracking-[0.22em] text-[--muted]">Narada Druk</p>
            <p className="text-sm font-semibold text-white">{product.priceLabel}</p>
          </div>
          <a className="accent-pill" href={product.telegramUrl} target="_blank" rel="noreferrer">
            Замовити
          </a>
        </div>
      </div>
    </main>
  );
}
