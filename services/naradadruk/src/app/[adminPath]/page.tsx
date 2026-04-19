import Image from "next/image";
import { assertAdminPath, getAdminRoute, isAdminAuthenticated } from "@/lib/auth";
import { getAdminDashboardData } from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import {
  createProductAction,
  deleteCategoryAction,
  logoutAction,
  saveCategoryAction,
  saveSettingsAction,
} from "@/app/actions/admin";
import { LoginForm } from "@/components/admin/login-form";
import { SubmitButton } from "@/components/admin/submit-button";

export const dynamic = "force-dynamic";

type AdminPageProps = {
  params: Promise<{ adminPath: string }>;
  searchParams: Promise<{ ok?: string; error?: string }>;
};

function Message({ ok, error }: { ok?: string; error?: string }) {
  if (ok) {
    return <div className="status-message status-message--ok">{ok}</div>;
  }

  if (error) {
    return <div className="status-message status-message--error">{error}</div>;
  }

  return null;
}

export default async function AdminPage({ params, searchParams }: AdminPageProps) {
  const [{ adminPath }, query] = await Promise.all([params, searchParams]);
  assertAdminPath(adminPath);

  if (!(await isAdminAuthenticated())) {
    return (
      <main className="mx-auto flex min-h-[80dvh] w-full max-w-[1400px] items-center px-4 py-12 md:px-6">
        <LoginForm />
      </main>
    );
  }

  const { categories, products, settings } = await getAdminDashboardData();

  return (
    <main className="mx-auto w-full max-w-[1400px] px-4 py-6 md:px-6 md:py-8">
      <div className="flex flex-col gap-4 border-b border-white/10 pb-6 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="text-xs uppercase tracking-[0.32em] text-[--accent]">Narada Druk admin</p>
          <h1 className="mt-3 font-display text-5xl tracking-[-0.06em] text-white">Керування каталогом</h1>
          <p className="mt-3 max-w-[60ch] text-sm leading-7 text-[--muted]">
            Окрема адмінка для storefront-текстів, категорій, товарів, варіантів і зображень.
          </p>
        </div>

        <div className="flex flex-wrap gap-3">
          <a className="ghost-pill" href={withBasePath("/catalog")}>
            Відкрити каталог
          </a>
          <form action={logoutAction}>
            <button type="submit" className="ghost-pill">
              Вийти
            </button>
          </form>
        </div>
      </div>

      <div className="mt-6">
        <Message ok={query.ok} error={query.error} />
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[0.56fr_0.44fr]">
        <section className="grid gap-6">
          <div className="glass-panel rounded-[2rem] p-6">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Storefront</p>
                <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">Тексти й основні CTA</h2>
              </div>
            </div>

            <form action={saveSettingsAction} className="mt-6 grid gap-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="field-shell md:col-span-2">
                  <span>Hero title</span>
                  <input name="heroTitle" defaultValue={settings.heroTitle} />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Hero subtitle</span>
                  <textarea name="heroSubtitle" defaultValue={settings.heroSubtitle} />
                </div>
                <div className="field-shell">
                  <span>Support title</span>
                  <input name="supportTitle" defaultValue={settings.supportTitle} />
                </div>
                <div className="field-shell">
                  <span>Telegram URL</span>
                  <input name="telegramUrl" defaultValue={settings.telegramUrl} />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Support body</span>
                  <textarea name="supportBody" defaultValue={settings.supportBody} />
                </div>
                <div className="field-shell">
                  <span>Materials note</span>
                  <input name="materialsNote" defaultValue={settings.materialsNote} />
                </div>
                <div className="field-shell">
                  <span>Lead time note</span>
                  <input name="leadTimeNote" defaultValue={settings.leadTimeNote} />
                </div>
                <div className="field-shell">
                  <span>Delivery note</span>
                  <input name="deliveryNote" defaultValue={settings.deliveryNote} />
                </div>
                <div className="field-shell">
                  <span>Payment note</span>
                  <input name="paymentNote" defaultValue={settings.paymentNote} />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Contact note</span>
                  <textarea name="contactNote" defaultValue={settings.contactNote} />
                </div>
              </div>

              <SubmitButton>Зберегти storefront</SubmitButton>
            </form>
          </div>

          <div className="glass-panel rounded-[2rem] p-6">
            <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Категорії</p>
            <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">Структура каталогу</h2>

            <form action={saveCategoryAction} className="mt-6 grid gap-4 rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="field-shell">
                  <span>Назва</span>
                  <input name="name" placeholder="Наприклад, 3D друк" />
                </div>
                <div className="field-shell">
                  <span>Slug</span>
                  <input name="slug" placeholder="Необов'язково" />
                </div>
                <div className="field-shell md:col-span-2">
                  <span>Опис</span>
                  <textarea name="description" placeholder="Короткий опис категорії" />
                </div>
                <div className="field-shell">
                  <span>Sort order</span>
                  <input name="sortOrder" type="number" defaultValue={0} />
                </div>
                <label className="field-shell justify-end">
                  <span>Видима категорія</span>
                  <input name="isVisible" type="checkbox" defaultChecked className="h-5 w-5" />
                </label>
              </div>
              <SubmitButton>Додати категорію</SubmitButton>
            </form>

            <div className="mt-6 grid gap-4">
              {categories.map((category) => (
                <div key={category.id} className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
                  <form action={saveCategoryAction} className="grid gap-4">
                    <input type="hidden" name="categoryId" value={category.id} />
                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="field-shell">
                        <span>Назва</span>
                        <input name="name" defaultValue={category.name} />
                      </div>
                      <div className="field-shell">
                        <span>Slug</span>
                        <input name="slug" defaultValue={category.slug} />
                      </div>
                      <div className="field-shell md:col-span-2">
                        <span>Опис</span>
                        <textarea name="description" defaultValue={category.description} />
                      </div>
                      <div className="field-shell">
                        <span>Sort order</span>
                        <input name="sortOrder" type="number" defaultValue={category.sortOrder} />
                      </div>
                      <label className="field-shell justify-end">
                        <span>Видима категорія</span>
                        <input name="isVisible" type="checkbox" defaultChecked={category.isVisible} className="h-5 w-5" />
                      </label>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <p className="text-sm text-[--muted]">{category._count.products} товарів</p>
                      <SubmitButton>Зберегти</SubmitButton>
                    </div>
                  </form>
                  <form action={deleteCategoryAction} className="mt-3">
                    <input type="hidden" name="categoryId" value={category.id} />
                    <button type="submit" className="ghost-pill">
                      Видалити
                    </button>
                  </form>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="grid gap-6">
          <div className="glass-panel rounded-[2rem] p-6">
            <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Новий товар</p>
            <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">Створити чернетку</h2>

            <form action={createProductAction} className="mt-6 grid gap-4">
              <div className="field-shell">
                <span>Назва товару</span>
                <input name="title" placeholder="Наприклад, стенд для мікрофона" />
              </div>
              <div className="field-shell">
                <span>Категорія</span>
                <select name="categoryId" defaultValue="">
                  <option value="" disabled>
                    Оберіть категорію
                  </option>
                  {categories.map((category) => (
                    <option key={category.id} value={category.id}>
                      {category.name}
                    </option>
                  ))}
                </select>
              </div>
              <SubmitButton>Створити товар</SubmitButton>
            </form>
          </div>

          <div className="glass-panel rounded-[2rem] p-6">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Товари</p>
                <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">Поточний асортимент</h2>
              </div>
              <span className="text-sm text-[--muted]">{products.length} позицій</span>
            </div>

            <div className="mt-6 grid gap-4">
              {products.length > 0 ? (
                products.map((product) => (
                  <div key={product.id} className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-4">
                    <div className="flex gap-4">
                      <div className="h-20 w-20 overflow-hidden rounded-[1rem] bg-[--surface-strong]">
                        {product.coverImage ? (
                          <Image
                            src={withBasePath(product.coverImage.urlPath)}
                            alt={product.coverImage.alt || product.title}
                            width={320}
                            height={240}
                            unoptimized
                            className="h-full w-full object-cover"
                          />
                        ) : (
                          <div className="product-placeholder h-full w-full">
                            <span>{product.category.name}</span>
                          </div>
                        )}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div>
                            <div className="font-display text-2xl tracking-[-0.04em] text-white">{product.title}</div>
                            <p className="mt-1 text-sm text-[--muted]">{product.category.name}</p>
                          </div>
                          <div className="text-right">
                            <div className="text-sm font-semibold text-white">{product.priceLabel}</div>
                            <div className="mt-1 text-xs uppercase tracking-[0.2em] text-[--muted]">
                              {product.status === "published" ? "Published" : "Draft"}
                            </div>
                          </div>
                        </div>
                        <p className="mt-3 line-clamp-2 text-sm leading-6 text-[--muted]">{product.shortDescription || "Опис ще не заповнений."}</p>
                        <div className="mt-4 flex flex-wrap gap-3">
                          <a className="accent-pill" href={withBasePath(`${getAdminRoute()}/products/${product.id}`)}>
                            Редагувати
                          </a>
                          <a className="ghost-pill" href={withBasePath(`/product/${product.slug}`)} target="_blank" rel="noreferrer">
                            Публічна сторінка
                          </a>
                        </div>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="rounded-[1.5rem] border border-white/10 bg-white/[0.03] p-5 text-sm leading-7 text-[--muted]">
                  Товари ще не додані. Створіть першу чернетку і перейдіть до детального редагування.
                </div>
              )}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
