import { OrderStatus } from "@prisma/client";
import { notFound } from "next/navigation";
import {
  formatOrderDate,
  formatOrderValue,
  orderStatusLabel,
  orderStatusLabels,
} from "@/components/admin/order-dashboard";
import { assertAdminPath, getAdminRoute, requireAdminSession } from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";
import { getAdminOrders } from "@/lib/data";

export const dynamic = "force-dynamic";

type OrdersPageProps = {
  params: Promise<{ adminPath: string }>;
  searchParams: Promise<{ status?: string; ok?: string; error?: string }>;
};

export default async function OrdersPage({ params, searchParams }: OrdersPageProps) {
  await requireAdminSession();
  const [{ adminPath }, query] = await Promise.all([params, searchParams]);
  assertAdminPath(adminPath);

  const workflowStatuses = [OrderStatus.new, OrderStatus.accepted, OrderStatus.shipped, OrderStatus.completed, OrderStatus.cancelled] as const;
  const status = query.status && workflowStatuses.includes(query.status as (typeof workflowStatuses)[number])
    ? query.status as (typeof workflowStatuses)[number]
    : undefined;
  if (query.status && !status) notFound();
  const orders = await getAdminOrders(status);
  const ordersPath = `${getAdminRoute()}/orders`;

  return (
    <main className="mx-auto w-full max-w-[1200px] px-4 py-6 md:px-6 md:py-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <a className="text-sm text-[--muted] transition hover:text-white" href={withBasePath(getAdminRoute())}>
            Повернутися до огляду
          </a>
          <h1 className="mt-4 font-display text-5xl tracking-[-0.06em] text-white">Замовлення</h1>
          <p className="mt-3 text-sm text-[--muted]">
            Показано до 200 останніх замовлень{status ? ` зі статусом «${orderStatusLabels[status]}»` : ""}.
          </p>
        </div>
      </div>

      {query.ok ? <div className="status-message status-message--ok mt-5">{query.ok}</div> : null}
      {query.error ? <div className="status-message status-message--error mt-5">{query.error}</div> : null}

      <nav className="mt-6 flex flex-wrap gap-2" aria-label="Фільтр статусу замовлень">
        <a className={!status ? "accent-pill" : "ghost-pill"} href={withBasePath(ordersPath)}>
          Усі
        </a>
        {workflowStatuses.map((item) => (
          <a
            className={status === item ? "accent-pill" : "ghost-pill"}
            href={withBasePath(`${ordersPath}?status=${item}`)}
            key={item}
          >
            {orderStatusLabels[item]}
          </a>
        ))}
      </nav>

      <section className="glass-panel mt-6 rounded-[2rem] p-6">
        <div className="grid gap-3">
          {orders.length > 0 ? (
            orders.map((order) => (
              <a
                className="grid gap-3 rounded-[1.35rem] border border-white/10 bg-white/[0.03] p-4 transition hover:border-white/20 hover:bg-white/[0.055] md:grid-cols-[1fr_auto_auto] md:items-center"
                href={withBasePath(`${ordersPath}/${order.publicId}`)}
                key={order.publicId}
              >
                <span>
                  <strong className="block text-white">{order.firstName} {order.lastName}</strong>
                  <small className="mt-1 block text-xs text-[--muted]">
                    {formatOrderDate(order.createdAt)} · {order._count.items} позицій · {order.source === "manual" ? "ручне" : "сайт"}
                  </small>
                </span>
                <span className="text-sm text-[--accent]">{orderStatusLabel(order.status)}</span>
                <strong className="text-white">{formatOrderValue(order.total)}</strong>
              </a>
            ))
          ) : (
            <p className="rounded-[1.35rem] border border-white/10 bg-white/[0.03] p-5 text-sm text-[--muted]">
              Замовлень за цим фільтром немає.
            </p>
          )}
        </div>
      </section>
    </main>
  );
}
