import { notFound } from "next/navigation";
import { deletePromoCodeAction, savePromoCodeAction } from "@/app/actions/admin";
import { assertAdminPath, getAdminRoute, requireAdminSession } from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";
import { getAdminPromoCode } from "@/lib/data";

export const dynamic = "force-dynamic";
const localDateTime = (value: Date | null) => value ? new Date(value.getTime() - value.getTimezoneOffset() * 60_000).toISOString().slice(0, 16) : "";

export default async function PromoCodePage({ params, searchParams }: { params: Promise<{ adminPath: string; promoId: string }>; searchParams: Promise<{ ok?: string; error?: string }> }) {
  await requireAdminSession(); const [{ adminPath, promoId }, query] = await Promise.all([params, searchParams]); assertAdminPath(adminPath);
  const promo = await getAdminPromoCode(Number(promoId)); if (!promo) notFound();
  return <main className="mx-auto w-full max-w-[1000px] px-4 py-6 md:px-6 md:py-8"><a className="text-sm text-[--muted]" href={withBasePath(`${getAdminRoute()}/promo-codes`)}>До промокодів</a><h1 className="mt-4 font-display text-5xl text-white">{promo.code}</h1>
    {query.ok ? <div className="status-message status-message--ok mt-5">{query.ok}</div> : null}{query.error ? <div className="status-message status-message--error mt-5">{query.error}</div> : null}
    <div className="mt-6 grid gap-6 lg:grid-cols-2"><section className="glass-panel rounded-[2rem] p-6"><form action={savePromoCodeAction} className="grid gap-4"><input type="hidden" name="id" value={promo.id} /><div className="field-shell"><span>Код</span><input name="code" defaultValue={promo.code} minLength={3} maxLength={32} required /><small>Українські або латинські літери, цифри, _ чи -.</small></div><div className="grid grid-cols-2 gap-3"><div className="field-shell"><span>Тип</span><select name="type" defaultValue={promo.type}><option value="percentage">Відсоток</option><option value="fixed">Фіксована сума</option></select></div><div className="field-shell"><span>Значення</span><input name="value" type="number" min="1" defaultValue={promo.value} required /></div></div><div className="field-shell"><span>Ліміт</span><input name="usageLimit" type="number" min="1" defaultValue={promo.usageLimit ?? ""} /></div><div className="field-shell"><span>Діє до</span><input name="expiresAt" type="datetime-local" defaultValue={localDateTime(promo.expiresAt)} /></div><label className="field-shell"><span>Увімкнений</span><input name="enabled" type="checkbox" defaultChecked={promo.enabled} className="h-5 w-5" /></label><button className="accent-pill" type="submit">Зберегти</button></form></section>
      <section className="glass-panel rounded-[2rem] p-6"><h2 className="font-display text-3xl text-white">Використання: {promo.useCount}</h2><div className="mt-4 grid gap-3">{promo.orders.length ? promo.orders.map((order) => <a className="rounded-xl border border-white/10 p-3 text-sm text-white" href={withBasePath(`${getAdminRoute()}/orders/${order.publicId}`)} key={order.publicId}>#{order.publicId.slice(0, 8).toUpperCase()} · −{order.discountAmount} грн · {order.total} грн</a>) : <p className="text-[--muted]">Замовлень із цим кодом ще немає.</p>}</div></section></div>
    <section className="glass-panel mt-6 rounded-[2rem] border border-red-400/20 p-6">
      <h2 className="font-display text-3xl text-white">Видалення промокоду</h2>
      {promo.useCount > 0 || promo.orders.length > 0 ? <p className="mt-3 text-sm text-[--muted]">Код уже використано, тому видалення недоступне. Вимкніть його у формі вище: історія замовлень і суми знижок залишаться збереженими.</p> : <form action={deletePromoCodeAction} className="mt-4 grid gap-4"><input type="hidden" name="promoId" value={promo.id} /><label className="flex items-start gap-3 text-sm text-[--muted]"><input className="mt-0.5 h-5 w-5" type="checkbox" name="confirmDelete" value="yes" required /><span>Підтверджую видалення невикористаного промокоду. Цю дію не можна скасувати.</span></label><button className="ghost-pill w-fit border-red-400/30 text-red-200" type="submit">Видалити промокод</button></form>}
    </section>
  </main>;
}
