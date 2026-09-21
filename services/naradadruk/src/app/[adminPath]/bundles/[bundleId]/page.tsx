import { notFound } from "next/navigation";
import { assertAdminPath, getAdminRoute, requireAdminSession } from "@/lib/auth";
import { getAdminBundle } from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import { deleteBundleAction, deleteBundleItemAction, saveBundleAction, saveBundleItemAction } from "@/app/actions/admin";
import { SubmitButton } from "@/components/admin/submit-button";

export const dynamic = "force-dynamic";

function productOptions(products: NonNullable<Awaited<ReturnType<typeof getAdminBundle>>>["products"]) {
  return products.flatMap((product) => product.variants.length
    ? product.variants.map((variant) => ({ value: `${product.id}:${variant.id}`, label: `${product.title} · ${variant.label}` }))
    : [{ value: `${product.id}:base`, label: product.title }]);
}

export default async function AdminBundlePage({ params, searchParams }: { params: Promise<{ adminPath: string; bundleId: string }>; searchParams: Promise<{ ok?: string; error?: string }> }) {
  await requireAdminSession();
  const [{ adminPath, bundleId }, query] = await Promise.all([params, searchParams]);
  assertAdminPath(adminPath);
  const id = Number(bundleId);
  if (!Number.isInteger(id) || id <= 0) notFound();
  const data = await getAdminBundle(id);
  if (!data) notFound();
  const { bundle, products } = data;
  const options = productOptions(products);
  return <main className="mx-auto w-full max-w-[1100px] px-4 py-6 md:px-6 md:py-8">
    <a className="text-sm text-[--muted]" href={withBasePath(`${getAdminRoute()}/bundles`)}>До комплектів</a>
    <div className="mt-4 flex flex-wrap items-start justify-between gap-4"><div><h1 className="font-display text-5xl tracking-[-0.06em] text-white">{bundle.title}</h1><p className={bundle.readiness.ready ? "mt-2 text-[--accent]" : "mt-2 text-amber-200"}>{bundle.readiness.reason}</p></div><span className={bundle.isVisible ? "text-[--accent]" : "text-[--muted]"}>{bundle.isVisible ? "Опубліковано" : "Приховано"}</span></div>
    {query.ok ? <div className="status-message status-message--ok mt-5">{query.ok}</div> : null}{query.error ? <div className="status-message status-message--error mt-5">{query.error}</div> : null}
    <div className="mt-6 grid gap-6 lg:grid-cols-2">
      <section className="glass-panel rounded-[2rem] p-6"><h2 className="font-display text-3xl text-white">Налаштування</h2><form action={saveBundleAction} className="mt-5 grid gap-4"><input type="hidden" name="id" value={bundle.id} /><div className="field-shell"><span>Назва</span><input name="title" defaultValue={bundle.title} /></div><div className="field-shell"><span>Slug</span><input name="slug" defaultValue={bundle.slug} /></div><div className="field-shell"><span>Короткий опис</span><textarea name="shortDescription" defaultValue={bundle.shortDescription} /></div><div className="field-shell"><span>Порядок</span><input name="sortOrder" type="number" defaultValue={bundle.sortOrder} /></div><label className="field-shell"><span>Показувати в каталозі</span><input name="isVisible" type="checkbox" defaultChecked={bundle.isVisible} className="h-5 w-5" /></label><SubmitButton>Зберегти комплект</SubmitButton></form></section>
      <section className="glass-panel rounded-[2rem] p-6"><h2 className="font-display text-3xl text-white">Додати позицію</h2><form action={saveBundleItemAction} className="mt-5 grid gap-4"><input type="hidden" name="bundleId" value={bundle.id} /><div className="field-shell"><span>Товар і варіант</span><select name="selection" required defaultValue=""><option value="" disabled>Оберіть позицію</option>{options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></div><div className="grid grid-cols-2 gap-4"><div className="field-shell"><span>Кількість</span><input name="quantity" type="number" min="1" max="20" defaultValue="1" /></div><div className="field-shell"><span>Порядок</span><input name="sortOrder" type="number" defaultValue="0" /></div></div><SubmitButton>Додати</SubmitButton></form></section>
    </div>
    <section className="glass-panel mt-6 rounded-[2rem] p-6"><h2 className="font-display text-3xl text-white">Склад комплекту</h2><div className="mt-5 grid gap-3">{bundle.items.length ? bundle.items.map((item) => <div key={item.id} className="rounded-[1.25rem] border border-white/10 bg-white/[.03] p-4"><form action={saveBundleItemAction} className="grid gap-4 md:grid-cols-[1fr_8rem_8rem_auto]"><input type="hidden" name="bundleId" value={bundle.id} /><input type="hidden" name="itemId" value={item.id} /><select name="selection" defaultValue={`${item.productId}:${item.variantId ?? "base"}`}>{options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select><input aria-label="Кількість" name="quantity" type="number" min="1" max="20" defaultValue={item.quantity} /><input aria-label="Порядок" name="sortOrder" type="number" defaultValue={item.sortOrder} /><SubmitButton>Оновити</SubmitButton></form><form action={deleteBundleItemAction} className="mt-3"><input type="hidden" name="bundleId" value={bundle.id} /><input type="hidden" name="itemId" value={item.id} /><button className="ghost-pill" type="submit">Видалити позицію</button></form></div>) : <p className="text-[--muted]">Додайте щонайменше дві позиції.</p>}</div></section>
    <form action={deleteBundleAction} className="mt-6"><input type="hidden" name="id" value={bundle.id} /><button className="ghost-pill" type="submit">Видалити комплект</button></form>
  </main>;
}
