import { getAdminRoute } from "@/lib/auth";
import { withBasePath } from "@/lib/base-path";

type OrderStatus =
  | "new"
  | "accepted"
  | "shipped"
  | "closed";

type OrderSummary = {
  totalCount: number;
  newCount: number;
  activeCount: number;
  acceptedCount: number;
  shippedCount: number;
  closedCount: number;
  byStatus: Record<OrderStatus, number>;
  allTimeOrderValue: number;
  recent: {
    days: number;
    count: number;
    orderValue: number;
  };
  recentOrders: Array<{
    publicId: string;
    status: string;
    firstName: string;
    lastName: string;
    total: number;
    createdAt: Date;
    _count: { items: number };
  }>;
};

export const orderStatusLabels: Record<OrderStatus, string> = {
  new: "Обробляється",
  accepted: "Прийнято в роботу",
  shipped: "Відправлене",
  closed: "Закрито",
};

export function orderStatusLabel(status: string) {
  if (status === "confirmed" || status === "processing") return orderStatusLabels.accepted;
  if (status === "completed" || status === "cancelled") return orderStatusLabels.closed;
  return orderStatusLabels[status as OrderStatus] ?? status;
}

const statusOrder = Object.keys(orderStatusLabels) as OrderStatus[];

export function formatOrderValue(value: number) {
  return `${new Intl.NumberFormat("uk-UA").format(value)} грн`;
}

export function formatOrderDate(value: Date) {
  return new Intl.DateTimeFormat("uk-UA", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Europe/Kyiv",
  }).format(value);
}

export function OrderDashboard({ summary }: { summary: OrderSummary }) {
  const metrics = [
    { label: "Усі замовлення", value: String(summary.totalCount) },
    { label: "Обробляються", value: String(summary.newCount) },
    { label: "Прийнято в роботу", value: String(summary.acceptedCount) },
    { label: "Відправлено", value: String(summary.shippedCount) },
    { label: "Закрито", value: String(summary.closedCount) },
    { label: "Загальна вартість замовлень", value: formatOrderValue(summary.allTimeOrderValue) },
  ];

  return (
    <section className="glass-panel mt-6 rounded-[2rem] p-6" id="orders">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.28em] text-[--accent]">Замовлення</p>
          <h2 className="mt-2 font-display text-3xl tracking-[-0.05em] text-white">
            Огляд замовлень
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-[--muted]">
            Суми нижче — вартість оформлених замовлень, а не підтверджена оплата чи
            бухгалтерська виручка.
          </p>
        </div>
        <a className="accent-pill" href={withBasePath(`${getAdminRoute()}/orders`)}>
          Усі замовлення
        </a>
      </div>

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {metrics.map((metric) => (
          <article
            className="rounded-[1.35rem] border border-white/10 bg-white/[0.035] p-4"
            key={metric.label}
          >
            <p className="text-xs uppercase tracking-[0.18em] text-[--muted]">{metric.label}</p>
            <strong className="mt-2 block font-display text-3xl tracking-[-0.04em] text-white">
              {metric.value}
            </strong>
          </article>
        ))}
      </div>

      <div className="mt-4 rounded-[1.35rem] border border-white/10 bg-black/15 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-[0.18em] text-[--muted]">
              Останні {summary.recent.days} днів
            </p>
            <p className="mt-1 text-sm text-white">
              {summary.recent.count} замовлень · {formatOrderValue(summary.recent.orderValue)}
              {" "}вартості замовлень
            </p>
          </div>
          <div className="flex flex-wrap gap-2" aria-label="Розподіл замовлень за статусом">
            {statusOrder.map((status) => (
              <a
                className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-xs text-[--muted] transition hover:border-white/20 hover:text-white"
                href={withBasePath(`${getAdminRoute()}/orders?status=${status}`)}
                key={status}
              >
                {orderStatusLabels[status]} · {summary.byStatus[status]}
              </a>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-6">
        <div className="flex items-center justify-between gap-4">
          <h3 className="font-display text-2xl tracking-[-0.04em] text-white">Останні замовлення</h3>
          <span className="text-xs text-[--muted]">до 5 останніх</span>
        </div>
        <div className="mt-3 grid gap-3">
          {summary.recentOrders.length > 0 ? (
            summary.recentOrders.map((order) => (
              <a
                className="flex flex-wrap items-center justify-between gap-3 rounded-[1.25rem] border border-white/10 bg-white/[0.03] p-4 transition hover:border-white/20 hover:bg-white/[0.055]"
                href={withBasePath(`${getAdminRoute()}/orders/${order.publicId}`)}
                key={order.publicId}
              >
                <span>
                  <strong className="block text-sm text-white">
                    {order.firstName} {order.lastName}
                  </strong>
                  <small className="mt-1 block text-xs text-[--muted]">
                    {formatOrderDate(order.createdAt)} · {order._count.items} позицій
                  </small>
                </span>
                <span className="text-right">
                  <strong className="block text-sm text-white">{formatOrderValue(order.total)}</strong>
                  <small className="mt-1 block text-xs text-[--accent]">
                    {orderStatusLabel(order.status)}
                  </small>
                </span>
              </a>
            ))
          ) : (
            <p className="rounded-[1.25rem] border border-white/10 bg-white/[0.03] p-4 text-sm text-[--muted]">
              Замовлень ще немає.
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
