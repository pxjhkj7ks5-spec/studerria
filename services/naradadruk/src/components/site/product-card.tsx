import Image from "next/image";
import { withBasePath } from "@/lib/base-path";

type ProductCardProps = {
  product: {
    slug: string;
    title: string;
    shortDescription: string;
    leadTime: string;
    priceLabel: string;
    category: { name: string };
    coverImage: { urlPath: string; alt: string } | null;
  };
  telegramUrl: string;
};

export function ProductCard({ product, telegramUrl }: ProductCardProps) {
  return (
    <article className="interactive-card group grid gap-4 rounded-[2rem] border border-white/10 bg-white/[0.04] p-4 transition duration-300 hover:border-white/20 hover:bg-white/[0.06] md:p-5">
      <a className="block overflow-hidden rounded-[1.5rem] bg-[--surface-strong]" href={withBasePath(`/product/${product.slug}`)}>
        {product.coverImage ? (
          <Image
            src={withBasePath(product.coverImage.urlPath)}
            alt={product.coverImage.alt || product.title}
            width={1200}
            height={900}
            unoptimized
            className="aspect-[4/3] h-full w-full object-cover transition duration-500 group-hover:scale-[1.02]"
          />
        ) : (
          <div className="product-placeholder aspect-[4/3] h-full w-full">
            <span>{product.category.name}</span>
          </div>
        )}
      </a>

      <div className="grid gap-3">
        <div className="flex items-center justify-between gap-3 text-xs uppercase tracking-[0.22em] text-[--muted]">
          <span>{product.category.name}</span>
          {product.leadTime ? <span>{product.leadTime}</span> : null}
        </div>

        <div>
          <a
            href={withBasePath(`/product/${product.slug}`)}
            className="font-display text-2xl tracking-[-0.05em] text-white transition group-hover:text-[--accent]"
          >
            {product.title}
          </a>
          <p className="mt-2 line-clamp-3 text-sm leading-6 text-[--muted]">{product.shortDescription}</p>
        </div>

        <div className="flex items-end justify-between gap-3">
          <p className="text-lg font-semibold text-white">{product.priceLabel}</p>
          <div className="flex gap-2">
            <a className="ghost-pill" href={withBasePath(`/product/${product.slug}`)}>
              Деталі
            </a>
            <a className="accent-pill" href={telegramUrl} target="_blank" rel="noreferrer">
              Замовити
            </a>
          </div>
        </div>
      </div>
    </article>
  );
}
