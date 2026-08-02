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
import { assessProductReadiness } from "@/lib/product-readiness";
import { calculatePrivatePriceGuidance } from "@/lib/product-content-package";

export const dynamic = "force-dynamic";

type ProductEditorPageProps = {
  params: Promise<{ adminPath: string; productId: string }>;
  searchParams: Promise<{ ok?: string; error?: string }>;
};

function dateTimeInput(value: Date | null) {
  return value ? new Date(value.getTime() - value.getTimezoneOffset() * 60_000).toISOString().slice(0, 16) : "";
}

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
  const readiness = assessProductReadiness(product);
  const privatePricing = calculatePrivatePriceGuidance(product.printWeightGrams, product.basePrice);

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
          {product.sourceTelegramUrl ? (
            <a
              className="ghost-pill"
              href={product.sourceTelegramUrl}
              target="_blank"
              rel="noreferrer"
            >
              Вихідний допис
            </a>
          ) : null}
          {product.sourceModelUrl ? (
            <a
              className="ghost-pill"
              href={product.sourceModelUrl}
              target="_blank"
              rel="noopener noreferrer"
            >
              MakerWorld
            </a>
          ) : null}
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

      <section className="glass-panel mt-6 rounded-[2rem] p-6">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Готовність до публікації</p>
            <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">
              {readiness.ready ? "Картка готова" : "Картку варто доповнити"}
            </h2>
            <p className="mt-2 text-sm text-[--muted]">
              Пройдено {readiness.passedCount} із {readiness.totalCount} перевірок якості.
            </p>
          </div>
          <strong className="font-display text-5xl tracking-[-0.06em] text-white">{readiness.score}%</strong>
        </div>
        <div className="mt-5 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {readiness.checks.map((check) => (
            <div className={check.passed ? "rounded-xl border border-emerald-400/20 bg-emerald-400/[0.06] px-3 py-2 text-sm text-emerald-100" : "rounded-xl border border-amber-400/20 bg-amber-400/[0.06] px-3 py-2 text-sm text-amber-100"} key={check.key}>
              <strong>{check.passed ? "Готово" : "Додайте"}</strong> · {check.label}
            </div>
          ))}
        </div>
      </section>

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
                <div className="md:col-span-2 rounded-[1.35rem] border border-red-400/20 bg-red-400/[0.04] p-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <label className="field-shell"><span>Активувати знижку</span><input name="saleEnabled" type="checkbox" defaultChecked={product.saleEnabled} className="h-5 w-5" /></label>
                    <p className="text-xs leading-5 text-[--muted]">Вкажіть або акційну ціну (варіанти зменшаться пропорційно), або відсоток для всіх цін. Одночасно обидва поля не заповнюйте.</p>
                    <div className="field-shell"><span>Акційна ціна, грн</span><input name="salePrice" type="number" min="0" defaultValue={product.salePrice ?? ""} /></div>
                    <div className="field-shell"><span>Знижка, %</span><input name="salePercent" type="number" min="1" max="99" defaultValue={product.salePercent ?? ""} /></div>
                    <div className="field-shell"><span>Початок (необов’язково)</span><input name="saleStartsAt" type="datetime-local" defaultValue={dateTimeInput(product.saleStartsAt)} /></div>
                    <div className="field-shell"><span>Завершення (необов’язково)</span><input name="saleEndsAt" type="datetime-local" defaultValue={dateTimeInput(product.saleEndsAt)} /></div>
                  </div>
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Короткий опис</span>
                  <textarea name="shortDescription" defaultValue={product.shortDescription} />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Повний опис</span>
                  <textarea name="fullDescription" defaultValue={product.fullDescription} />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Окремий текст Telegram</span>
                  <textarea name="telegramDescription" defaultValue={product.telegramDescription} />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Для кого / сценарій використання</span>
                  <textarea name="useCaseNote" defaultValue={product.useCaseNote} />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Переваги, кожна з нового рядка</span>
                  <textarea name="benefitsNote" defaultValue={product.benefitsNote} />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Характеристики, кожна з нового рядка</span>
                  <textarea name="specificationsNote" defaultValue={product.specificationsNote} />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Сумісність</span>
                  <textarea name="compatibilityNote" defaultValue={product.compatibilityNote} />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Комплектація</span>
                  <textarea name="packageContentsNote" defaultValue={product.packageContentsNote} />
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
                <div className="md:col-span-2 rounded-[1.35rem] border border-amber-300/20 bg-amber-300/[0.04] p-4">
                  <p className="text-xs uppercase tracking-[0.22em] text-amber-200">Приватні дані — не показуються покупцям</p>
                  <div className="mt-4 grid gap-4 md:grid-cols-2">
                    <div className="field-shell">
                      <span>Вага друку, г</span>
                      <input name="printWeightGrams" type="number" min="1" defaultValue={product.printWeightGrams ?? ""} />
                    </div>
                    <div className="rounded-xl border border-white/10 bg-black/10 p-4 text-sm leading-6 text-[--muted]">
                      {privatePricing.minimumPrice === null || privatePricing.suggestedPrice === null ? (
                        "Вкажіть вагу, щоб отримати приватну підказку."
                      ) : (
                        <>
                          Мінімум: <strong className="text-white">{privatePricing.minimumPrice} грн</strong><br />
                          Підказка: <strong className="text-white">{privatePricing.suggestedPrice} грн</strong>
                          {privatePricing.belowMinimum ? <span className="mt-2 block text-amber-200">Поточна ціна нижча за мінімум.</span> : null}
                        </>
                      )}
                    </div>
                    <div className="field-shell md:col-span-2">
                      <span>Джерело MakerWorld</span>
                      <input name="sourceModelUrl" type="url" defaultValue={product.sourceModelUrl} />
                    </div>
                    <div className="field-shell">
                      <span>Автор моделі</span>
                      <input name="sourceModelAuthor" defaultValue={product.sourceModelAuthor} />
                    </div>
                    <div className="field-shell">
                      <span>Ліцензія</span>
                      <input name="sourceModelLicense" defaultValue={product.sourceModelLicense} />
                    </div>
                    <label className="field-shell justify-end md:col-span-2">
                      <span>Ліцензію перевірено вручну</span>
                      <input name="sourceLicenseChecked" type="checkbox" defaultChecked={product.sourceLicenseChecked} className="h-5 w-5" />
                    </label>
                  </div>
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
