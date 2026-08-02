import { savePromoCodeAction } from "@/app/actions/admin";
import { assertAdminPath, getAdminRoute, requireAdminSession } from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";
import { getAdminPromoCodes } from "@/lib/data";

export const dynamic = "force-dynamic";

export default async function PromoCodesPage({ params, searchParams }: { params: Promise<{ adminPath: string }>; searchParams: Promise<{ ok?: string; error?: string }> }) {
  await requireAdminSession();
  const [{ adminPath }, query] = await Promise.all([params, searchParams]);
  assertAdminPath(adminPath);
  const promos = await getAdminPromoCodes();
  const base = `${getAdminRoute()}/promo-codes`;
  return <main className="mx-auto w-full max-w-[1200px] px-4 py-6 md:px-6 md:py-8">
    <a className="text-sm text-[--muted]" href={withBasePath(getAdminRoute())}>Повернутися до огляду</a>
    <h1 className="mt-4 font-display text-5xl tracking-[-0.06em] text-white">Промокоди</h1>
    <p className="mt-3 text-sm text-[--muted]">Ліміт і дата завершення незалежні. Якщо обидва порожні, код безстроковий і необмежений.</p>
    {query.ok ? <div className="status-message status-message--ok mt-5">{query.ok}</div> : null}{query.error ? <div className="status-message status-message--error mt-5">{query.error}</div> : null}
    <div className="mt-6 grid gap-6 lg:grid-cols-[.42fr_.58fr]">
      <section className="glass-panel rounded-[2rem] p-6"><h2 className="font-display text-3xl text-white">Створити код</h2><form action={savePromoCodeAction} className="mt-5 grid gap-4">
        <div className="field-shell"><span>Код</span><input name="code" placeholder="НАРАДА-10" minLength={3} maxLength={32} required /><small>Українські або латинські літери, цифри, _ чи -.</small></div>
        <div className="grid grid-cols-2 gap-3"><div className="field-shell"><span>Тип</span><select name="type"><option value="percentage">Відсоток</option><option value="fixed">Фіксована сума, грн</option></select></div><div className="field-shell"><span>Значення</span><input name="value" type="number" min="1" required /></div></div>
        <div className="field-shell"><span>Ліміт використань (необов’язково)</span><input name="usageLimit" type="number" min="1" /></div>
        <div className="field-shell"><span>Діє до (необов’язково)</span><input name="expiresAt" type="datetime-local" /></div>
        <label className="field-shell"><span>Увімкнений</span><input name="enabled" type="checkbox" defaultChecked className="h-5 w-5" /></label>
        <button className="accent-pill" type="submit">Створити промокод</button>
      </form></section>
      <section className="glass-panel rounded-[2rem] p-6"><h2 className="font-display text-3xl text-white">Видані коди</h2><div className="mt-5 grid gap-3">{promos.length ? promos.map((promo) => <a className="rounded-[1.25rem] border border-white/10 bg-white/[.03] p-4" href={withBasePath(`${base}/${promo.id}`)} key={promo.id}><span className="flex justify-between gap-3"><strong className="text-white">{promo.code}</strong><span className={promo.enabled ? "text-[--accent]" : "text-[--muted]"}>{promo.enabled ? "Активний" : "Вимкнений"}</span></span><small className="mt-2 block text-[--muted]">{promo.type === "percentage" ? `${promo.value}%` : `${promo.value} грн`} · {promo.useCount}{promo.usageLimit === null ? " використань" : ` / ${promo.usageLimit} використань`}{promo.expiresAt ? ` · до ${new Intl.DateTimeFormat("uk-UA", { dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Kyiv" }).format(promo.expiresAt)}` : " · безстроково"}</small></a>) : <p className="text-[--muted]">Промокодів ще немає.</p>}</div></section>
    </div>
  </main>;
}
