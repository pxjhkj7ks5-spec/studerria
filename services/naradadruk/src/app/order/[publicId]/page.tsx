import { CheckCircle, Package, Truck } from "@phosphor-icons/react/ssr";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { PublicFrame } from "@/components/site/public-frame";
import { getOrderByPublicId, getSiteSettings } from "@/lib/data";
import { withBasePath } from "@/lib/base-path";
import { formatPrice } from "@/lib/utils";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { robots: { index: false, follow: false } };

const deliveryLabels = { branch: "Відділення Нової пошти", parcel_locker: "Поштомат Нової пошти", courier: "Курʼєр Нової пошти" } as const;
const paymentLabels = { cash_on_delivery: "Післяплата", transfer: "Переказ після підтвердження" } as const;
const statusLabels = { new: "Нове", confirmed: "Підтверджено", processing: "Виготовляється", shipped: "Відправлено", completed: "Виконано", cancelled: "Скасовано" } as const;

export default async function OrderPage({ params }: { params: Promise<{ publicId: string }> }) {
  const { publicId } = await params;
  const [settings, order] = await Promise.all([getSiteSettings(), getOrderByPublicId(publicId)]);
  if (!order) notFound();
  const destination = order.deliveryMethod === "courier" ? order.courierAddress : order.deliveryDestination;

  return (
    <PublicFrame telegramUrl={settings.telegramUrl}>
      <main className="order-page site-container">
        <section className="order-confirmation">
          <div className="order-confirmation__mark"><CheckCircle aria-hidden size={38} weight="fill" /></div>
          <p className="eyebrow">Замовлення прийнято</p>
          <h1>Дякуємо, {order.firstName}.</h1>
          <p>Ми отримали замовлення й звʼяжемося з вами в Telegram для підтвердження.</p>
          <div className="order-reference"><span>Номер</span><strong>{order.publicId.slice(0, 8).toUpperCase()}</strong><span>Статус</span><strong>{statusLabels[order.status]}</strong></div>
        </section>

        <div className="order-summary-grid">
          <section className="order-summary">
            <div className="order-summary__heading"><Package aria-hidden size={22} /><h2>Склад замовлення</h2></div>
            <div className="order-summary__items">
              {order.items.map((item) => (
                <article key={item.id}>
                  <div><a href={item.productUrl}>{item.productTitle}</a>{item.variantLabel ? <span>{item.variantLabel}</span> : null}<small>{item.quantity} × {formatPrice(item.unitPrice)}</small></div>
                  <strong>{formatPrice(item.totalPrice)}</strong>
                </article>
              ))}
            </div>
            <div className="order-summary__total"><span>Разом за товари</span><strong>{formatPrice(order.total)}</strong></div>
          </section>

          <section className="order-summary">
            <div className="order-summary__heading"><Truck aria-hidden size={22} /><h2>Отримання й оплата</h2></div>
            <dl>
              <div><dt>Одержувач</dt><dd>{order.firstName} {order.lastName}</dd></div>
              <div><dt>Телефон</dt><dd>{order.phone}</dd></div>
              <div><dt>Telegram</dt><dd>{order.telegramContact}</dd></div>
              <div><dt>Доставка</dt><dd>{deliveryLabels[order.deliveryMethod]}</dd></div>
              <div><dt>Місто</dt><dd>{order.cityName}</dd></div>
              <div><dt>Точка</dt><dd>{destination}</dd></div>
              <div><dt>Оплата</dt><dd>{paymentLabels[order.paymentMethod]}</dd></div>
            </dl>
            {order.paymentMethod === "transfer" ? <div className="payment-note"><strong>Що далі</strong><p>Реквізити для оплати надійдуть після підтвердження замовлення.</p></div> : null}
          </section>
        </div>

        <div className="order-actions"><a className="accent-pill accent-pill--large" href={withBasePath("/catalog")}>Повернутися до каталогу</a><a className="ghost-pill ghost-pill--large" href={withBasePath("/")}>На головну</a></div>
      </main>
    </PublicFrame>
  );
}
