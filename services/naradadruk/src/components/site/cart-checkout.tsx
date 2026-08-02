"use client";

import Image from "next/image";
import { useEffect, useState, type FormEvent } from "react";
import {
  ArrowLeft,
  Check,
  Minus,
  Package,
  Plus,
  ShoppingBag,
  Trash,
  Truck,
} from "@phosphor-icons/react";
import { useCart } from "@/components/site/cart-provider";
import { withBasePath } from "@/lib/base-path";
import { formatPrice } from "@/lib/utils";

type Option = { ref: string; label: string; secondary: string };
type DeliveryMethod = "branch" | "parcel_locker" | "courier";
type PaymentMethod = "cash_on_delivery" | "transfer";

export function CartCheckout() {
  const { items, hydrated, total, updateQuantity, removeItem, clearCart } = useCart();
  const [cityName, setCityName] = useState("");
  const [cityRef, setCityRef] = useState("");
  const [cityOptions, setCityOptions] = useState<Option[]>([]);
  const [deliveryMethod, setDeliveryMethod] = useState<DeliveryMethod>("branch");
  const [destination, setDestination] = useState("");
  const [destinationRef, setDestinationRef] = useState("");
  const [destinationOptions, setDestinationOptions] = useState<Option[]>([]);
  const [paymentMethod, setPaymentMethod] = useState<PaymentMethod>("cash_on_delivery");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (cityRef) {
      setCityOptions([]);
      return;
    }
    const controller = new AbortController();
    const timeout = window.setTimeout(async () => {
      try {
        const response = await fetch(withBasePath(`/api/nova-poshta/cities?q=${encodeURIComponent(cityName)}`), {
          signal: controller.signal,
        });
        const payload = (await response.json()) as { options?: Option[] };
        setCityOptions(payload.options ?? []);
      } catch {
        if (!controller.signal.aborted) setCityOptions([]);
      }
    }, 250);
    return () => {
      window.clearTimeout(timeout);
      controller.abort();
    };
  }, [cityName, cityRef]);

  useEffect(() => {
    if (deliveryMethod === "courier" || !cityRef || destinationRef) {
      setDestinationOptions([]);
      return;
    }
    const controller = new AbortController();
    const timeout = window.setTimeout(async () => {
      try {
        const params = new URLSearchParams({ cityRef, method: deliveryMethod, q: destination });
        const response = await fetch(withBasePath(`/api/nova-poshta/warehouses?${params}`), {
          signal: controller.signal,
        });
        const payload = (await response.json()) as { options?: Option[] };
        setDestinationOptions(payload.options ?? []);
      } catch {
        if (!controller.signal.aborted) setDestinationOptions([]);
      }
    }, 250);
    return () => {
      window.clearTimeout(timeout);
      controller.abort();
    };
  }, [cityRef, deliveryMethod, destination, destinationRef]);

  function chooseCity(option: Option) {
    setCityName(option.label);
    setCityRef(option.ref);
    setCityOptions([]);
    setDestination("");
    setDestinationRef("");
  }

  function chooseDestination(option: Option) {
    setDestination(option.label);
    setDestinationRef(option.ref);
    setDestinationOptions([]);
  }

  async function submitOrder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (items.length === 0 || isSubmitting) return;
    setIsSubmitting(true);
    setError("");
    const form = new FormData(event.currentTarget);

    try {
      const response = await fetch(withBasePath("/api/orders"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          firstName: form.get("firstName"),
          lastName: form.get("lastName"),
          comment: form.get("comment"),
          phone: form.get("phone"),
          telegramContact: form.get("telegramContact"),
          cityName,
          cityRef,
          deliveryMethod,
          deliveryDestination: destination,
          destinationRef,
          courierAddress: deliveryMethod === "courier" ? destination : "",
          paymentMethod,
          items: items.map((item) => ({
            productId: item.productId,
            variantId: item.variantId,
            quantity: item.quantity,
          })),
        }),
      });
      const payload = (await response.json()) as { publicId?: string; error?: string };
      if (!response.ok || !payload.publicId) throw new Error(payload.error || "Не вдалося оформити замовлення.");
      clearCart();
      window.location.assign(withBasePath(`/order/${payload.publicId}`));
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : "Не вдалося оформити замовлення.");
      setIsSubmitting(false);
    }
  }

  if (!hydrated) {
    return <div className="cart-skeleton" aria-label="Завантаження кошика"><span /><span /><span /></div>;
  }

  if (items.length === 0) {
    return (
      <section className="cart-empty">
        <span className="cart-empty__icon"><ShoppingBag aria-hidden size={34} /></span>
        <p className="eyebrow">Кошик порожній</p>
        <h1>Оберіть готові вироби в каталозі.</h1>
        <p>Можна додати кілька товарів і оформити їх одним замовленням.</p>
        <a className="accent-pill accent-pill--large" href={withBasePath("/catalog")}>Перейти до каталогу</a>
      </section>
    );
  }

  return (
    <form className="checkout-layout" onSubmit={submitOrder}>
      <section className="cart-column">
        <a className="back-link" href={withBasePath("/catalog")}><ArrowLeft aria-hidden size={18} /> Продовжити покупки</a>
        <div className="checkout-heading">
          <p className="eyebrow">Ваше замовлення</p>
          <h1>Кошик</h1>
          <p>{items.length} {items.length === 1 ? "позиція" : "позиції"} в одному відправленні.</p>
        </div>

        <div className="cart-list">
          {items.map((item) => (
            <article className="cart-item" key={item.key}>
              <a className="cart-item__image" href={withBasePath(`/product/${item.productSlug}`)}>
                {item.imageUrl ? (
                  <Image src={withBasePath(item.imageUrl)} alt={item.productTitle} width={180} height={140} unoptimized />
                ) : <Package aria-hidden size={28} />}
              </a>
              <div className="cart-item__body">
                <a href={withBasePath(`/product/${item.productSlug}`)}><strong>{item.productTitle}</strong></a>
                {item.variantLabel ? <span>{item.variantLabel}</span> : null}
                <small>{formatPrice(item.unitPrice)} за одиницю</small>
              </div>
              <div className="quantity-control" aria-label={`Кількість ${item.productTitle}`}>
                <button type="button" onClick={() => updateQuantity(item.key, item.quantity - 1)} aria-label="Зменшити кількість"><Minus aria-hidden size={15} /></button>
                <span>{item.quantity}</span>
                <button type="button" onClick={() => updateQuantity(item.key, item.quantity + 1)} aria-label="Збільшити кількість"><Plus aria-hidden size={15} /></button>
              </div>
              <strong className="cart-item__total">{formatPrice(item.unitPrice * item.quantity)}</strong>
              <button className="cart-item__remove" type="button" onClick={() => removeItem(item.key)} aria-label={`Видалити ${item.productTitle}`}><Trash aria-hidden size={18} /></button>
            </article>
          ))}
        </div>

        <div className="cart-total"><span>Разом за товари</span><strong>{formatPrice(total)}</strong></div>
      </section>

      <section className="checkout-panel">
        <div className="checkout-panel__heading">
          <span><Truck aria-hidden size={22} /></span>
          <div><p className="eyebrow">Оформлення</p><h2>Контакти й доставка</h2></div>
        </div>

        <div className="form-grid form-grid--two">
          <label><span>Імʼя</span><input name="firstName" autoComplete="given-name" minLength={2} maxLength={60} required /></label>
          <label><span>Прізвище</span><input name="lastName" autoComplete="family-name" minLength={2} maxLength={60} required /></label>
          <label><span>Телефон</span><input name="phone" type="tel" autoComplete="tel" placeholder="+380…" required /><small>Для даних одержувача та уточнень.</small></label>
          <label><span>Telegram для підтвердження</span><input name="telegramContact" placeholder="@username або номер" required /><small>Майстерня підтвердить деталі тут.</small></label>
        </div>

        <label className="form-field form-field--options">
          <span>Місто</span>
          <input value={cityName} onChange={(event) => { setCityName(event.target.value); setCityRef(""); }} autoComplete="address-level2" placeholder="Почніть вводити місто" required />
          {cityOptions.length > 0 ? <div className="option-list">{cityOptions.map((option, index) => <button type="button" key={`${option.ref}:${option.label}:${index}`} onClick={() => chooseCity(option)}><strong>{option.label}</strong><small>{option.secondary}</small></button>)}</div> : null}
          <small>Якщо API недоступний, введене місто буде збережено вручну.</small>
        </label>

        <fieldset className="choice-group">
          <legend>Спосіб доставки Новою поштою</legend>
          {([
            ["branch", "Відділення"],
            ["parcel_locker", "Поштомат"],
            ["courier", "Курʼєр"],
          ] as const).map(([value, label]) => (
            <label key={value} className={deliveryMethod === value ? "is-active" : ""}>
              <input type="radio" name="deliveryMethod" value={value} checked={deliveryMethod === value} onChange={() => { setDeliveryMethod(value); setDestination(""); setDestinationRef(""); }} />
              <span><Check aria-hidden size={15} /> {label}</span>
            </label>
          ))}
        </fieldset>

        <label className="form-field form-field--options">
          <span>{deliveryMethod === "courier" ? "Адреса доставки" : deliveryMethod === "parcel_locker" ? "Поштомат" : "Відділення"}</span>
          <input value={destination} onChange={(event) => { setDestination(event.target.value); setDestinationRef(""); }} autoComplete={deliveryMethod === "courier" ? "street-address" : "off"} placeholder={deliveryMethod === "courier" ? "Вулиця, будинок, квартира" : "Номер або адреса"} required />
          {destinationOptions.length > 0 ? <div className="option-list">{destinationOptions.map((option) => <button type="button" key={option.ref} onClick={() => chooseDestination(option)}><strong>{option.label}</strong><small>{option.secondary}</small></button>)}</div> : null}
          {deliveryMethod !== "courier" && !cityRef ? <small>Оберіть місто зі списку для офіційного переліку або введіть точку вручну.</small> : null}
        </label>

        <fieldset className="choice-group choice-group--payment">
          <legend>Оплата</legend>
          <label className={paymentMethod === "cash_on_delivery" ? "is-active" : ""}><input type="radio" name="paymentMethod" checked={paymentMethod === "cash_on_delivery"} onChange={() => setPaymentMethod("cash_on_delivery")} /><span><Check aria-hidden size={15} /> Післяплата</span><small>Оплата під час отримання.</small></label>
          <label className={paymentMethod === "transfer" ? "is-active" : ""}><input type="radio" name="paymentMethod" checked={paymentMethod === "transfer"} onChange={() => setPaymentMethod("transfer")} /><span><Check aria-hidden size={15} /> Переказ після підтвердження</span><small>Власник підтвердить замовлення та надасть реквізити особисто в Telegram або телефоном.</small></label>
        </fieldset>

        <label className="form-field"><span>Коментар</span><textarea name="comment" rows={4} maxLength={1200} placeholder="Колір, побажання або уточнення до замовлення" /></label>

        {error ? <div className="checkout-error" role="alert">{error}</div> : null}
        <button className="accent-pill accent-pill--large checkout-submit" type="submit" disabled={isSubmitting}>
          {isSubmitting ? "Оформлюємо…" : `Оформити на ${formatPrice(total)}`}
        </button>
        <p className="checkout-consent">Після оформлення ви побачите номер і статус замовлення. Вартість доставки сплачується окремо за тарифами Нової пошти.</p>
      </section>
    </form>
  );
}
