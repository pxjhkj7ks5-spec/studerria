import { notFound } from "next/navigation";
import {
  formatOrderDate,
  formatOrderValue,
  orderStatusLabel,
  orderStatusLabels,
} from "@/components/admin/order-dashboard";
import { assertAdminPath, getAdminRoute, requireAdminSession } from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";
import { getAdminOrderByPublicId } from "@/lib/data";
import { addOrderCommentAction, updateOrderStatusAction } from "@/app/actions/admin";

export const dynamic = "force-dynamic";

const deliveryLabels = {
  branch: "Відділення Нової пошти",
  parcel_locker: "Поштомат Нової пошти",
  courier: "Курʼєр Нової пошти",
} as const;

const paymentLabels = {
  cash_on_delivery: "Післяплата",
  transfer: "Переказ після підтвердження",
} as const;

export default async function OrderDetailsPage({
  params,
  searchParams,
}: {
  params: Promise<{ adminPath: string; publicId: string }>;
  searchParams: Promise<{ ok?: string; error?: string }>;
}) {
  await requireAdminSession();
  const [{ adminPath, publicId }, query] = await Promise.all([params, searchParams]);
  assertAdminPath(adminPath);
  const order = await getAdminOrderByPublicId(publicId);
  if (!order) notFound();

  const destination = order.deliveryMethod === "courier"
    ? order.courierAddress || order.deliveryDestination
    : order.deliveryDestination;

  return (
    <main className="mx-auto w-full max-w-[1100px] px-4 py-6 md:px-6 md:py-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <a
            className="text-sm text-[--muted] transition hover:text-white"
            href={withBasePath(`${getAdminRoute()}/orders`)}
          >
            Повернутися до замовлень
          </a>
          <h1 className="mt-4 font-display text-4xl tracking-[-0.06em] text-white md:text-5xl">
            Замовлення {order.publicId.slice(0, 8)}
          </h1>
          <p className="mt-3 text-sm text-[--muted]">
            {formatOrderDate(order.createdAt)} · {orderStatusLabel(order.status)} · {order.source === "manual" ? "Ручне" : "Із сайту"}
          </p>
        </div>
        {order.source === "website" ? <a
          className="ghost-pill"
          href={withBasePath(`/order/${order.publicId}`)}
          target="_blank"
          rel="noopener noreferrer"
        >
          Сторінка покупця
        </a> : null}
      </div>
      {query.ok ? <div className="status-message status-message--ok mt-5">{query.ok}</div> : null}
      {query.error ? <div className="status-message status-message--error mt-5">{query.error}</div> : null}

      <section className="glass-panel mt-6 rounded-[2rem] p-6">
        <h2 className="font-display text-3xl text-white">Керування</h2>
        <div className="mt-4 flex flex-wrap gap-2">{Object.entries(orderStatusLabels).map(([status, label]) => <form action={updateOrderStatusAction} key={status}><input type="hidden" name="publicId" value={order.publicId} /><input type="hidden" name="status" value={status} /><button className={order.status === status ? "accent-pill" : "ghost-pill"} type="submit">{label}</button></form>)}</div>
        <form action={addOrderCommentAction} className="mt-5 flex flex-col gap-3 md:flex-row"><input type="hidden" name="publicId" value={order.publicId} /><input className="min-w-0 flex-1" name="comment" maxLength={1000} placeholder="Внутрішній коментар менеджера" required /><button className="ghost-pill" type="submit">Додати коментар</button></form>
      </section>

      <div className="mt-6 grid gap-6 lg:grid-cols-[0.58fr_0.42fr]">
        <section className="glass-panel rounded-[2rem] p-6">
          <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Склад</p>
          <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">Товари</h2>
          <div className="mt-5 grid gap-3">
            {order.items.map((item) => (
              <article className="rounded-[1.25rem] border border-white/10 bg-white/[0.03] p-4" key={item.id}>
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <strong className="text-white">{item.productTitle}</strong>
                    <p className="mt-1 text-xs text-[--muted]">
                      {item.variantLabel || "Базовий варіант"} · {item.quantity} шт.
                    </p>
                  </div>
                  <strong className="whitespace-nowrap text-white">{formatOrderValue(item.totalPrice)}</strong>
                </div>
                {item.productUrl ? (
                  <a className="mt-3 inline-flex text-xs font-semibold text-[--accent]" href={item.productUrl} target="_blank" rel="noopener noreferrer">
                    Відкрити товар
                  </a>
                ) : null}
              </article>
            ))}
          </div>
          <div className="mt-5 flex items-center justify-between border-t border-white/10 pt-5">
            <span className="text-sm text-[--muted]">{order.saleDiscountAmount || order.discountAmount ? "Звичайна вартість" : "Загальна вартість замовлення"}</span>
            <strong className="font-display text-3xl tracking-[-0.04em] text-white">
              {formatOrderValue(order.saleDiscountAmount || order.discountAmount ? order.subtotal : order.total)}
            </strong>
          </div>
          {order.saleDiscountAmount > 0 ? <div className="mt-2 flex justify-between text-sm text-[--muted]"><span>Знижка на товари</span><strong>−{formatOrderValue(order.saleDiscountAmount)}</strong></div> : null}
          {order.discountAmount > 0 ? <div className="mt-2 flex justify-between text-sm text-[--muted]"><span>Промокод {order.promoCodeSnapshot}</span><strong>−{formatOrderValue(order.discountAmount)}</strong></div> : null}
          {order.saleDiscountAmount || order.discountAmount ? <div className="mt-4 flex justify-between border-t border-white/10 pt-4 text-white"><span>Фінальна сума</span><strong>{formatOrderValue(order.total)}</strong></div> : null}
          <p className="mt-2 text-xs leading-5 text-[--muted]">
            Це сума замовлення, не підтвердження фактично отриманої оплати.
          </p>
        </section>

        <section className="glass-panel rounded-[2rem] p-6">
          <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Покупець</p>
          <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">Контакт і доставка</h2>
          <dl className="mt-5 grid gap-4 text-sm">
            <div><dt className="text-[--muted]">Імʼя</dt><dd className="mt-1 text-white">{order.firstName} {order.lastName}</dd></div>
            <div><dt className="text-[--muted]">Телефон</dt><dd className="mt-1 text-white">{order.phone}</dd></div>
            <div><dt className="text-[--muted]">Telegram</dt><dd className="mt-1 text-white">{order.telegramContact}</dd></div>
            <div><dt className="text-[--muted]">Доставка</dt><dd className="mt-1 text-white">{deliveryLabels[order.deliveryMethod]}</dd></div>
            <div><dt className="text-[--muted]">Місто</dt><dd className="mt-1 text-white">{order.cityName}</dd></div>
            <div><dt className="text-[--muted]">Точка / адреса</dt><dd className="mt-1 text-white">{destination}</dd></div>
            <div><dt className="text-[--muted]">Оплата</dt><dd className="mt-1 text-white">{paymentLabels[order.paymentMethod]}</dd></div>
            <div><dt className="text-[--muted]">Telegram-сповіщення</dt><dd className="mt-1 text-white">{order.notificationStatus}</dd></div>
          </dl>
          {order.comment ? (
            <div className="mt-5 rounded-[1.25rem] border border-white/10 bg-white/[0.03] p-4">
              <strong className="text-sm text-white">Коментар</strong>
              <p className="mt-2 whitespace-pre-line text-sm leading-6 text-[--muted]">{order.comment}</p>
            </div>
          ) : null}
        </section>
      </div>
      <section className="glass-panel mt-6 rounded-[2rem] p-6"><h2 className="font-display text-3xl text-white">Історія та внутрішні коментарі</h2><div className="mt-4 grid gap-3">{order.events.map((event) => <article className="rounded-xl border border-white/10 p-4" key={event.id}><strong className="text-white">{event.eventType === "comment" ? "Коментар" : event.eventType === "created" ? "Створено" : `${event.fromStatus ? orderStatusLabel(event.fromStatus) : ""} → ${orderStatusLabel(event.toStatus)}`}</strong>{event.comment ? <p className="mt-2 whitespace-pre-wrap text-sm text-[--muted]">{event.comment}</p> : null}<small className="mt-2 block text-[--muted]">{formatOrderDate(event.createdAt)} · {event.actor}</small></article>)}</div></section>
    </main>
  );
}
