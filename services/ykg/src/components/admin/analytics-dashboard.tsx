import type { CSSProperties } from "react";
import {
  ArrowDownRight,
  ArrowUpRight,
  CursorClick,
  Eye,
  PaperPlaneTilt,
  Users,
} from "@phosphor-icons/react/ssr";
import { withBasePath } from "@/lib/base-path";
import { getAdminRoute } from "@/lib/auth";
import {
  analyticsRanges,
  type AnalyticsReport,
} from "@/lib/analytics-report";
import type { AnalyticsEventName } from "@/lib/analytics";

type AnalyticsDashboardProps = {
  report: AnalyticsReport;
  productTitles: Record<string, string>;
};

const eventLabels: Record<AnalyticsEventName, string> = {
  "Page View": "Перегляд сторінки",
  "Catalog Open": "Відкриття каталогу",
  "Product Open": "Відкриття товару",
  "Catalog Filter": "Пошук або фільтр",
  "Add to Cart": "Додавання в кошик",
  "Checkout Open": "Початок оформлення",
  "Order Placed": "Оформлене замовлення",
  "Telegram Lead": "Перехід в Instagram",
  "Custom Lead": "Запит на власний виріб",
};

const periodLabels = {
  7: "7 днів",
  30: "30 днів",
  90: "90 днів",
} as const;

const dateTimeFormatter = new Intl.DateTimeFormat("uk-UA", {
  timeZone: "Europe/Kyiv",
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
});

function Delta({ value }: { value: number | null }) {
  if (value === null) {
    return <span className="admin-delta admin-delta--new">нове</span>;
  }

  if (value === 0) {
    return <span className="admin-delta">без змін</span>;
  }

  const positive = value > 0;

  return (
    <span
      className={`admin-delta ${
        positive ? "admin-delta--positive" : "admin-delta--negative"
      }`}
    >
      {positive ? (
        <ArrowUpRight aria-hidden size={13} weight="bold" />
      ) : (
        <ArrowDownRight aria-hidden size={13} weight="bold" />
      )}
      {Math.abs(value)}%
    </span>
  );
}

function Metric({
  icon,
  label,
  value,
  delta,
  note,
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  delta: number | null;
  note: string;
}) {
  return (
    <div className="admin-metric">
      <div className="admin-metric__header">
        <span className="admin-metric__icon">{icon}</span>
        <span>{label}</span>
      </div>
      <div className="admin-metric__value">{value}</div>
      <div className="admin-metric__footer">
        <Delta value={delta} />
        <span>{note}</span>
      </div>
    </div>
  );
}

function readablePath(path: string) {
  const normalized = path.replace(/^\/ykg/, "") || "/";

  if (normalized === "/") {
    return "Головна";
  }

  if (normalized === "/catalog") {
    return "Каталог";
  }

  if (normalized.startsWith("/product/")) {
    return `Товар · ${normalized.replace("/product/", "")}`;
  }

  if (normalized.startsWith("/category/")) {
    return `Категорія · ${normalized.replace("/category/", "")}`;
  }

  return normalized;
}

export function AnalyticsDashboard({
  report,
  productTitles,
}: AnalyticsDashboardProps) {
  const maxDailyValue = Math.max(
    1,
    ...report.daily.flatMap((day) => [day.views, day.clicks]),
  );
  const maxActionCount = Math.max(1, ...report.actions.map((item) => item.count));
  const commerceStages = [
    { label: "Перегляди", value: report.current.views, rate: 100 },
    { label: "Товари", value: report.commerce.productOpens, rate: report.commerce.viewToProductRate },
    { label: "Кошик", value: report.commerce.addToCarts, rate: report.commerce.productToCartRate },
    { label: "Оформлення", value: report.commerce.checkouts, rate: report.commerce.cartToCheckoutRate },
    { label: "Замовлення", value: report.commerce.orders, rate: report.commerce.checkoutToOrderRate },
  ];

  return (
    <section className="admin-analytics" id="analytics">
      <div className="admin-section-heading">
        <div>
          <p className="admin-kicker">Статистика</p>
          <h2>Що роблять відвідувачі</h2>
          <p>
            Перегляди, кліки та переходи в Instagram за київським часом.
            Особисті дані й IP не зберігаються.
          </p>
        </div>

        <nav className="admin-range" aria-label="Період статистики">
          {analyticsRanges.map((range) => (
            <a
              key={range}
              className={range === report.range ? "is-active" : ""}
              href={withBasePath(`${getAdminRoute()}?range=${range}#analytics`)}
            >
              {periodLabels[range]}
            </a>
          ))}
        </nav>
      </div>

      <div className="admin-metrics" aria-label="Ключові показники">
        <Metric
          icon={<Eye aria-hidden size={19} />}
          label="Перегляди"
          value={report.current.views}
          delta={report.deltas.views}
          note="до попереднього періоду"
        />
        <Metric
          icon={<CursorClick aria-hidden size={19} />}
          label="Кліки"
          value={report.current.clicks}
          delta={report.deltas.clicks}
          note="по товарах і кнопках"
        />
        <Metric
          icon={<PaperPlaneTilt aria-hidden size={19} />}
          label="Переходи в Instagram"
          value={report.current.leads}
          delta={report.deltas.leads}
          note={`${report.conversionRate}% від переглядів`}
        />
        <Metric
          icon={<Users aria-hidden size={19} />}
          label="Відвідувачі"
          value={report.current.sessions}
          delta={report.deltas.sessions}
          note="анонімні сесії"
        />
      </div>

      <section className="admin-commerce" aria-labelledby="commerce-funnel-title">
        <div className="admin-commerce__heading">
          <div>
            <h3 id="commerce-funnel-title">Воронка замовлення</h3>
            <p>Від перегляду сторінок до завершеного оформлення.</p>
          </div>
          <div className="admin-commerce__revenue">
            <span>Оборот із сайту</span>
            <strong>{new Intl.NumberFormat("uk-UA").format(report.commerce.revenue)} грн</strong>
            <small>{report.commerce.viewToOrderRate}% замовлень від переглядів</small>
          </div>
        </div>
        <ol className="admin-funnel">
          {commerceStages.map((stage, index) => (
            <li key={stage.label}>
              <span>{index + 1}</span>
              <div>
                <small>{stage.label}</small>
                <strong>{stage.value}</strong>
              </div>
              <em>{index === 0 ? "старт" : `${stage.rate}%`}</em>
            </li>
          ))}
        </ol>
        {report.funnelInsight ? (
          <div className="admin-commerce__insight" role="status">
            <strong>{report.funnelInsight.title}</strong>
            <span>
              Конверсія на цьому кроці: {report.funnelInsight.rate}%. {report.funnelInsight.message}
            </span>
          </div>
        ) : null}
      </section>

      <div className="admin-analytics__primary">
        <div className="admin-chart-panel">
          <div className="admin-chart-panel__header">
            <div>
              <h3>Активність за днями</h3>
              <p>Точна кількість переглядів і кліків у кожен день.</p>
            </div>
            <div className="admin-chart-legend" aria-label="Легенда">
              <span><i className="is-views" /> Перегляди</span>
              <span><i className="is-clicks" /> Кліки</span>
            </div>
          </div>

          {report.hasData ? (
            <div className="admin-chart-scroll">
              <div
                className="admin-chart"
                style={
                  {
                    "--chart-columns": report.daily.length,
                    "--chart-min-width": `${Math.max(620, report.daily.length * 22)}px`,
                  } as CSSProperties
                }
              >
                {report.daily.map((day, index) => (
                  <div
                    className="admin-chart__day"
                    key={day.key}
                    aria-label={`${day.label}: ${day.views} переглядів, ${day.clicks} кліків, ${day.leads} переходів в Instagram`}
                    title={`${day.label}: ${day.views} переглядів · ${day.clicks} кліків · ${day.leads} Instagram`}
                  >
                    <div className="admin-chart__bars">
                      <span
                        className="admin-chart__bar admin-chart__bar--views"
                        style={
                          {
                            "--bar-height": `${(day.views / maxDailyValue) * 100}%`,
                          } as CSSProperties
                        }
                      />
                      <span
                        className="admin-chart__bar admin-chart__bar--clicks"
                        style={
                          {
                            "--bar-height": `${(day.clicks / maxDailyValue) * 100}%`,
                          } as CSSProperties
                        }
                      />
                    </div>
                    <span
                      className={
                        index === 0 ||
                        index === report.daily.length - 1 ||
                        index % Math.max(1, Math.floor(report.daily.length / 6)) === 0
                          ? "admin-chart__label is-visible"
                          : "admin-chart__label"
                      }
                    >
                      {day.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="admin-empty-state">
              <strong>Статистика починає накопичуватися</strong>
              <span>
                Після цього оновлення тут зʼявляться реальні перегляди, кліки
                та переходи в Instagram.
              </span>
            </div>
          )}
        </div>

        <aside className="admin-actions-panel">
          <div>
            <h3>Популярні дії</h3>
            <p>Що натискають найчастіше.</p>
          </div>
          {report.actions.length > 0 ? (
            <ol className="admin-ranking">
              {report.actions.map((item) => (
                <li key={item.name}>
                  <div>
                    <span>{eventLabels[item.name]}</span>
                    <strong>{item.count}</strong>
                  </div>
                  <i
                    style={
                      {
                        "--ranking-width": `${(item.count / maxActionCount) * 100}%`,
                      } as CSSProperties
                    }
                  />
                </li>
              ))}
            </ol>
          ) : (
            <p className="admin-empty-copy">Ще немає кліків за цей період.</p>
          )}
        </aside>
      </div>

      <div className="admin-analytics__details">
        <section>
          <div className="admin-detail-heading">
            <div>
              <h3>Товари з найбільшим інтересом</h3>
              <p>Відкриття карток і переходи до замовлення.</p>
            </div>
          </div>
          {report.topProducts.length > 0 ? (
            <div className="admin-data-list">
              {report.topProducts.map((product, index) => (
                <div className="admin-data-row" key={product.slug}>
                  <span className="admin-data-row__index">{index + 1}</span>
                  <div className="admin-data-row__main">
                    <strong>{productTitles[product.slug] ?? product.slug}</strong>
                    <span>{product.opens} відкриттів · {product.carts} у кошик</span>
                  </div>
                  <div className="admin-data-row__value">
                    {product.leads} в Instagram
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="admin-empty-copy">Інтерес до товарів ще не зафіксований.</p>
          )}
        </section>

        <section>
          <div className="admin-detail-heading">
            <div>
              <h3>Найчастіше переглядають</h3>
              <p>Сторінки, які приводять до взаємодії.</p>
            </div>
          </div>
          {report.topPages.length > 0 ? (
            <div className="admin-data-list">
              {report.topPages.map((page, index) => (
                <div className="admin-data-row" key={page.key}>
                  <span className="admin-data-row__index">{index + 1}</span>
                  <div className="admin-data-row__main">
                    <strong>{readablePath(page.key)}</strong>
                    <span>{page.key}</span>
                  </div>
                  <div className="admin-data-row__value">{page.count}</div>
                </div>
              ))}
            </div>
          ) : (
            <p className="admin-empty-copy">Переглядів сторінок ще немає.</p>
          )}
        </section>
      </div>

      {report.recentEvents.length > 0 ? (
        <details className="admin-recent-events">
          <summary>Останні події</summary>
          <div className="admin-recent-events__list">
            {report.recentEvents.map((event) => (
              <div key={event.id}>
                <time>{dateTimeFormatter.format(event.createdAt)}</time>
                <strong>
                  {eventLabels[event.name as AnalyticsEventName] ?? event.name}
                </strong>
                <span>
                  {event.productSlug
                    ? productTitles[event.productSlug] ?? event.productSlug
                    : readablePath(event.path)}
                </span>
              </div>
            ))}
          </div>
        </details>
      ) : null}
    </section>
  );
}
