import Image from "next/image";
import { notFound } from "next/navigation";
import { assertAdminPath, getAdminRoute, requireAdminSession } from "@/lib/auth";
import { getAdminProductById } from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import {
  deleteProductAction,
  deleteProductImageAction,
  deleteVariantAction,
  saveVariantAction,
  setCoverImageAction,
  updateProductAction,
  updateProductImageAction,
  uploadProductImageAction,
} from "@/app/actions/admin";
import { SubmitButton } from "@/components/admin/submit-button";

export const dynamic = "force-dynamic";

type ProductEditorPageProps = {
  params: Promise<{ adminPath: string; productId: string }>;
  searchParams: Promise<{ ok?: string; error?: string }>;
};

export default async function ProductEditorPage({ params, searchParams }: ProductEditorPageProps) {
  await requireAdminSession();

  const [{ adminPath, productId }, query] = await Promise.all([params, searchParams]);
  assertAdminPath(adminPath);

  const resolvedProductId = Number(productId);

  if (!Number.isInteger(resolvedProductId) || resolvedProductId <= 0) {
    notFound();
  }

  const data = await getAdminProductById(resolvedProductId);

  if (!data) {
    notFound();
  }

  const { product, categories, settings } = data;

  return (
    <main className="mx-auto w-full max-w-[1400px] px-4 py-6 md:px-6 md:py-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <a className="text-sm text-[--muted] transition hover:text-white" href={withBasePath(getAdminRoute())}>
            Повернутися до адмінки
          </a>
          <h1 className="mt-4 font-display text-5xl tracking-[-0.06em] text-white">{product.title}</h1>
          <p className="mt-3 max-w-[60ch] text-sm leading-7 text-[--muted]">
            Редагування контенту, варіантів і медіа для конкретної позиції каталогу.
          </p>
        </div>

        <div className="flex flex-wrap gap-3">
          <a className="ghost-pill" href={withBasePath(`/product/${product.slug}`)} target="_blank" rel="noreferrer">
            Відкрити публічну сторінку
          </a>
          <a className="accent-pill" href={settings.telegramUrl} target="_blank" rel="noreferrer">
            Telegram
          </a>
        </div>
      </div>

      <div className="mt-6">
        {query.ok ? <div className="status-message status-message--ok">{query.ok}</div> : null}
        {query.error ? <div className="status-message status-message--error">{query.error}</div> : null}
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[0.6fr_0.4fr]">
        <section className="grid gap-6">
          <div className="glass-panel rounded-[2rem] p-6">
            <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Основна форма</p>
            <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">Контент товару</h2>

            <form action={updateProductAction} className="mt-6 grid gap-4">
              <input type="hidden" name="productId" value={product.id} />

              <div className="grid gap-4 md:grid-cols-2">
                <div className="field-shell">
                  <span>Назва</span>
                  <input name="title" defaultValue={product.title} />
                </div>
                <div className="field-shell">
                  <span>Slug</span>
                  <input name="slug" defaultValue={product.slug} />
                </div>
                <div className="field-shell">
                  <span>Категорія</span>
                  <select name="categoryId" defaultValue={product.categoryId}>
                    {categories.map((category) => (
                      <option key={category.id} value={category.id}>
                        {category.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field-shell">
                  <span>Статус</span>
                  <select name="status" defaultValue={product.status}>
                    <option value="draft">draft</option>
                    <option value="published">published</option>
                  </select>
                </div>
                <div className="field-shell">
                  <span>Базова ціна, грн</span>
                  <input name="basePrice" type="number" defaultValue={product.basePrice ?? ""} />
                </div>
                <div className="field-shell">
                  <span>Sort order</span>
                  <input name="sortOrder" type="number" defaultValue={product.sortOrder} />
                </div>
                <label className="field-shell justify-end">
                  <span>Показувати як “від ціни”</span>
                  <input name="priceFrom" type="checkbox" defaultChecked={product.priceFrom} className="h-5 w-5" />
                </label>
                <label className="field-shell justify-end">
                  <span>Featured</span>
                  <input name="isFeatured" type="checkbox" defaultChecked={product.isFeatured} className="h-5 w-5" />
                </label>
                <div className="field-shell md:col-span-2">
                  <span>Короткий опис</span>
                  <textarea name="shortDescription" defaultValue={product.shortDescription} />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Повний опис</span>
                  <textarea name="fullDescription" defaultValue={product.fullDescription} />
                </div>
                <div className="field-shell">
                  <span>Lead time</span>
                  <input name="leadTime" defaultValue={product.leadTime} />
                </div>
                <div className="field-shell">
                  <span>Material note</span>
                  <input name="materialNote" defaultValue={product.materialNote} />
                </div>
                <div className="field-shell">
                  <span>Delivery note</span>
                  <input name="deliveryNote" defaultValue={product.deliveryNote} />
                </div>
                <div className="field-shell">
                  <span>Payment note</span>
                  <input name="paymentNote" defaultValue={product.paymentNote} />
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3">
                <SubmitButton>Зберегти товар</SubmitButton>
                <div className="text-sm text-[--muted]">Поточна ціна: {product.priceLabel}</div>
              </div>
            </form>
          </div>

          <div className="glass-panel rounded-[2rem] p-6">
            <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Варіанти</p>
            <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">Розміри, кольори, комплектації</h2>

            <form action={saveVariantAction} className="mt-6 grid gap-4 rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
              <input type="hidden" name="productId" value={product.id} />
              <div className="grid gap-4 md:grid-cols-2">
                <div className="field-shell">
                  <span>Label</span>
                  <input name="label" placeholder="Мала / Чорна / Комплект 2 шт" />
                </div>
                <div className="field-shell">
                  <span>Ціна, грн</span>
                  <input name="price" type="number" />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Опис</span>
                  <input name="description" placeholder="Коротке уточнення про варіант" />
                </div>
                <div className="field-shell">
                  <span>Sort order</span>
                  <input name="sortOrder" type="number" defaultValue={0} />
                </div>
              </div>
              <SubmitButton>Додати варіант</SubmitButton>
            </form>

            <div className="mt-6 grid gap-4">
              {product.variants.length > 0 ? (
                product.variants.map((variant) => (
                  <div key={variant.id} className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
                    <form action={saveVariantAction} className="grid gap-4">
                      <input type="hidden" name="productId" value={product.id} />
                      <input type="hidden" name="variantId" value={variant.id} />
                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="field-shell">
                          <span>Label</span>
                          <input name="label" defaultValue={variant.label} />
                        </div>
                        <div className="field-shell">
                          <span>Ціна, грн</span>
                          <input name="price" type="number" defaultValue={variant.price} />
                        </div>
                        <div className="field-shell md:col-span-2">
                          <span>Опис</span>
                          <input name="description" defaultValue={variant.description} />
                        </div>
                        <div className="field-shell">
                          <span>Sort order</span>
                          <input name="sortOrder" type="number" defaultValue={variant.sortOrder} />
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-3">
                        <SubmitButton>Оновити варіант</SubmitButton>
                      </div>
                    </form>
                    <form action={deleteVariantAction} className="mt-3">
                      <input type="hidden" name="productId" value={product.id} />
                      <input type="hidden" name="variantId" value={variant.id} />
                      <button type="submit" className="ghost-pill">
                        Видалити
                      </button>
                    </form>
                  </div>
                ))
              ) : (
                <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4 text-sm text-[--muted]">
                  Варіантів поки немає. Якщо базової ціни достатньо, цей блок можна залишити порожнім.
                </div>
              )}
            </div>
          </div>
        </section>

        <section className="grid gap-6">
          <div className="glass-panel rounded-[2rem] p-6">
            <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Галерея</p>
            <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">Зображення товару</h2>

            <form action={uploadProductImageAction} className="mt-6 grid gap-4 rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
              <input type="hidden" name="productId" value={product.id} />
              <div className="field-shell">
                <span>Файл</span>
                <input name="image" type="file" accept="image/png,image/jpeg,image/webp,image/avif,image/gif" />
              </div>
              <div className="field-shell">
                <span>Alt text</span>
                <input name="alt" placeholder="Опис зображення" />
              </div>
              <div className="field-shell">
                <span>Sort order</span>
                <input name="sortOrder" type="number" defaultValue={0} />
              </div>
              <SubmitButton>Завантажити зображення</SubmitButton>
            </form>

            <div className="mt-6 grid gap-4">
              {product.images.length > 0 ? (
                product.images.map((image) => (
                  <div key={image.id} className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
                    <div className="overflow-hidden rounded-[1.25rem] bg-[--surface-strong]">
                      <Image
                        src={withBasePath(image.urlPath)}
                        alt={image.alt || product.title}
                        width={1200}
                        height={900}
                        unoptimized
                        className="aspect-[4/3] h-full w-full object-cover"
                      />
                    </div>

                    <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                      <div className="text-sm text-[--muted]">
                        {image.isCover ? "Поточна обкладинка" : "Додаткове зображення"}
                      </div>
                      {!image.isCover ? (
                        <form action={setCoverImageAction}>
                          <input type="hidden" name="productId" value={product.id} />
                          <input type="hidden" name="imageId" value={image.id} />
                          <button type="submit" className="ghost-pill">
                            Зробити обкладинкою
                          </button>
                        </form>
                      ) : null}
                    </div>

                    <form action={updateProductImageAction} className="mt-4 grid gap-4">
                      <input type="hidden" name="productId" value={product.id} />
                      <input type="hidden" name="imageId" value={image.id} />
                      <div className="field-shell">
                        <span>Alt text</span>
                        <input name="alt" defaultValue={image.alt} />
                      </div>
                      <div className="field-shell">
                        <span>Sort order</span>
                        <input name="sortOrder" type="number" defaultValue={image.sortOrder} />
                      </div>
                      <div className="flex flex-wrap gap-3">
                        <SubmitButton>Оновити зображення</SubmitButton>
                      </div>
                    </form>
                    <form action={deleteProductImageAction} className="mt-3">
                      <input type="hidden" name="productId" value={product.id} />
                      <input type="hidden" name="imageId" value={image.id} />
                      <button type="submit" className="ghost-pill">
                        Видалити
                      </button>
                    </form>
                  </div>
                ))
              ) : (
                <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4 text-sm text-[--muted]">
                  Для публікації потрібне хоча б одне зображення.
                </div>
              )}
            </div>
          </div>

          <div className="glass-panel rounded-[2rem] p-6">
            <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Danger zone</p>
            <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">Видалення товару</h2>
            <p className="mt-3 text-sm leading-7 text-[--muted]">
              Видалення прибере товар, варіанти і записи зображень. Файли з диска теж будуть прибрані.
            </p>
            <form action={deleteProductAction} className="mt-6">
              <input type="hidden" name="productId" value={product.id} />
              <button type="submit" className="ghost-pill">
                Видалити товар
              </button>
            </form>
          </div>
        </section>
      </div>
    </main>
  );
}
