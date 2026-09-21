import { assertAdminPath, getAdminRoute, requireAdminSession } from "@/lib/auth";
import { getAdminBundles } from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import { saveBundleAction } from "@/app/actions/admin";
import { SubmitButton } from "@/components/admin/submit-button";

export const dynamic = "force-dynamic";

export default async function AdminBundlesPage({ params, searchParams }: { params: Promise<{ adminPath: string }>; searchParams: Promise<{ ok?: string; error?: string }> }) {
  await requireAdminSession();
  const [{ adminPath }, query, bundles] = await Promise.all([params, searchParams, getAdminBundles()]);
  assertAdminPath(adminPath);
  return <main className="mx-auto w-full max-w-[1100px] px-4 py-6 md:px-6 md:py-8">
    <a className="text-sm text-[--muted]" href={withBasePath(getAdminRoute())}>До панелі</a>
    <div className="mt-4"><p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Каталог</p><h1 className="mt-2 font-display text-5xl tracking-[-0.06em] text-white">Комплекти</h1></div>
    {query.ok ? <div className="status-message status-message--ok mt-5">{query.ok}</div> : null}
    {query.error ? <div className="status-message status-message--error mt-5">{query.error}</div> : null}
    <div className="mt-6 grid gap-6 lg:grid-cols-[0.62fr_0.38fr]">
      <section className="glass-panel rounded-[2rem] p-6"><h2 className="font-display text-3xl text-white">Створені комплекти</h2><div className="mt-5 grid gap-3">{bundles.length ? bundles.map((bundle) => <a className="rounded-[1.25rem] border border-white/10 bg-white/[.03] p-4" href={withBasePath(`${getAdminRoute()}/bundles/${bundle.id}`)} key={bundle.id}><span className="flex items-center justify-between gap-3"><strong className="text-white">{bundle.title}</strong><span className={bundle.isVisible ? "text-[--accent]" : "text-[--muted]"}>{bundle.isVisible ? "Опубліковано" : "Приховано"}</span></span><small className="mt-2 block text-[--muted]">{bundle.items.length} позицій · {bundle.readiness.reason}</small></a>) : <p className="text-[--muted]">Комплектів ще немає.</p>}</div></section>
      <section className="glass-panel rounded-[2rem] p-6"><h2 className="font-display text-3xl text-white">Новий комплект</h2><form action={saveBundleAction} className="mt-5 grid gap-4"><div className="field-shell"><span>Назва</span><input name="title" required /></div><div className="field-shell"><span>Короткий опис</span><textarea name="shortDescription" required /></div><div className="field-shell"><span>Порядок</span><input name="sortOrder" type="number" defaultValue="0" /></div><SubmitButton>Створити чернетку</SubmitButton></form></section>
    </div>
  </main>;
}
