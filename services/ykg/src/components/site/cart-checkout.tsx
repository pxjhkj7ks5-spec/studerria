"use client";

import Image from "next/image";
import { useEffect, useRef, useState, type FormEvent } from "react";
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
import { trackAnalytics } from "@/lib/analytics";
import { withBasePath } from "@/lib/base-path";
import { formatPrice } from "@/lib/utils";

type Option = { ref: string; label: string; secondary: string };
type DeliveryMethod = "branch" | "parcel_locker" | "courier";
type PaymentMethod = "cash_on_delivery" | "transfer";
type PromoPreview = { code: string; subtotal: number; saleDiscountAmount: number; discountAmount: number; total: number; label: string };

export function CartCheckout() {
  const { items, hydrated, total, updateQuantity, removeItem, clearCart } = useCart();
  const [cityName, setCityName] = useState("");
  const [cityRef, setCityRef] = useState("");
  const [cityOptions, setCityOptions] = useState<Option[]>([]);
  const [deliveryMethod, setDeliveryMethod] = useState<DeliveryMethod>("branch");
  const [destination, setDestination] = useState("");
  const [destinationRef, setDestinationRef] = useState("");
  const [destinationOptions, setDestinationOptions] = useState<Option[]>([]);
  const [activeSuggestionField, setActiveSuggestionField] = useState<"city" | "destination" | null>(null);
  const [paymentMethod, setPaymentMethod] = useState<PaymentMethod>("transfer");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [promoCode, setPromoCode] = useState("");
  const [promo, setPromo] = useState<PromoPreview | null>(null);
  const [promoError, setPromoError] = useState("");
  const checkoutTracked = useRef(false);
  const regularTotal = items.reduce((sum, item) => sum + item.regularUnitPrice * item.quantity, 0);

  useEffect(() => {
    if (!hydrated || items.length === 0 || checkoutTracked.current) return;
    checkoutTracked.current = true;
    trackAnalytics("Checkout Open", {
      location: "cart",
      intent: "product",
      value: total,
      items: items.reduce((sum, item) => sum + item.quantity, 0),
    });
  }, [hydrated, items, total]);

  useEffect(() => { setPromo(null); setPromoError(""); }, [total]);

  async function applyPromo() {
    setPromoError("");
    try {
      const response = await fetch(withBasePath("/api/promo-codes/validate"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: promoCode, items: items.map((item) => ({ productId: item.productId, variantId: item.variantId, quantity: item.quantity })) }),
      });
      const payload = await response.json() as Partial<PromoPreview> & { error?: string };
      if (!response.ok || !payload?.code) throw new Error(payload?.error || "Промокод недійсний.");
      setPromo(payload as PromoPreview);
      setPromoCode(payload.code);
    } catch (promoFailure) {
      setPromo(null);
      setPromoError(promoFailure instanceof Error ? promoFailure.message : "Промокод недійсний.");
    }
  }

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
    setActiveSuggestionField(null);
  }

  function chooseDestination(option: Option) {
    setDestination(option.label);
    setDestinationRef(option.ref);
    setDestinationOptions([]);
    setActiveSuggestionField(null);
  }

  function closeSuggestions(field: "city" | "destination") {
    window.setTimeout(() => {
      setActiveSuggestionField((current) => (current === field ? null : current));
    }, 150);
  }

  async function submitOrder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (items.length === 0 || isSubmitting) return;
    if (promoCode.trim() && !promo) {
      setError("Застосуйте промокод або очистьте поле перед оформленням.");
      return;
    }
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
          promoCode: promo?.code ?? "",
          items: items.map((item) => ({
            productId: item.productId,
            variantId: item.variantId,
            quantity: item.quantity,
          })),
        }),
      });
      const payload = (await response.json()) as { publicId?: string; total?: number; error?: string };
      if (!response.ok || !payload.publicId) throw new Error(payload.error || "Не вдалося оформити замовлення.");
      trackAnalytics("Order Placed", {
        location: "checkout-success",
        intent: "product",
        value: payload.total ?? promo?.total ?? total,
        items: items.reduce((sum, item) => sum + item.quantity, 0),
      });
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
    <form className="checkout-layout" onSubmit={submitOrder} onReset={() => setPaymentMethod("transfer")}>
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
                <small>{item.regularUnitPrice > item.unitPrice ? <><del className="old-price">{formatPrice(item.regularUnitPrice)}</del> <strong>{formatPrice(item.unitPrice)}</strong> за одиницю</> : <>{formatPrice(item.unitPrice)} за одиницю</>}</small>
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

        {regularTotal > total ? <div className="cart-total"><span>Звичайна ціна</span><del className="old-price">{formatPrice(regularTotal)}</del><span>Знижка на товари</span><strong>−{formatPrice(regularTotal - total)}</strong></div> : null}
        <div className="cart-total"><span>Разом за товари</span><strong>{formatPrice(total)}</strong></div>
        <div className="promo-box">
          <label className="form-field"><span>Промокод</span><div className="promo-box__row"><input value={promoCode} onChange={(event) => { setPromoCode(event.target.value.toUpperCase()); setPromo(null); }} maxLength={32} placeholder="Введіть код" /><button className="ghost-pill" type="button" onClick={applyPromo}>Застосувати</button></div></label>
          {promo ? <div className="promo-summary"><span>Промокод {promo.code} ({promo.label})</span><strong>− {formatPrice(promo.discountAmount)}</strong><span>Фінальна сума</span><strong>{formatPrice(promo.total)}</strong></div> : null}
          {promoError ? <p className="checkout-error" role="alert">{promoError}</p> : null}
        </div>
      </section>

      <section className="checkout-panel">
        <div className="checkout-panel__heading">
          <span><Truck aria-hidden size={22} /></span>
          <div><p className="eyebrow">Оформлення</p><h2>Контакти й доставка</h2></div>
        </div>

        <div className="form-grid form-grid--two">
          <label><span>Імʼя</span><input name="firstName" autoComplete="given-name" minLength={2} maxLength={60} required /></label>
          <label><span>Прізвище</span><input name="lastName" autoComplete="family-name" minLength={2} maxLength={60} required /></label>
          <label><span>Телефон</span><input name="phone" type="tel" autoComplete="tel" placeholder="+380…" required /><small>Для даних одержувача Нової пошти.</small></label>
          <label><span>Telegram для звʼязку</span><input name="telegramContact" placeholder="@username або номер" minLength={3} maxLength={80} required /><small>Для підтвердження деталей замовлення.</small></label>
        </div>

        <label className="form-field form-field--options">
          <span>Місто</span>
          <input value={cityName} onChange={(event) => { setCityName(event.target.value); setCityRef(""); }} onFocus={() => setActiveSuggestionField("city")} onBlur={() => closeSuggestions("city")} autoComplete="address-level2" placeholder="Почніть вводити місто" minLength={2} maxLength={120} required />
          {activeSuggestionField === "city" && cityOptions.length > 0 ? <div className="option-list">{cityOptions.map((option, index) => <button type="button" key={`${option.ref}:${option.label}:${index}`} onClick={() => chooseCity(option)}><strong>{option.label}</strong>{option.secondary ? <small>{option.secondary}</small> : null}</button>)}</div> : null}
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
        <p className="checkout-delivery-note">
          Вартість доставки розраховує Нова пошта за чинними тарифами та сплачується окремо.
        </p>

        <label className="form-field form-field--options">
          <span>{deliveryMethod === "courier" ? "Адреса доставки" : deliveryMethod === "parcel_locker" ? "Поштомат" : "Відділення"}</span>
          <input value={destination} onChange={(event) => { setDestination(event.target.value); setDestinationRef(""); }} onFocus={() => setActiveSuggestionField("destination")} onBlur={() => closeSuggestions("destination")} autoComplete={deliveryMethod === "courier" ? "street-address" : "off"} placeholder={deliveryMethod === "courier" ? "Вулиця, будинок, квартира" : "Номер або адреса"} minLength={deliveryMethod === "courier" ? 5 : 1} maxLength={240} required />
          {activeSuggestionField === "destination" && destinationOptions.length > 0 ? <div className="option-list">{destinationOptions.map((option) => <button type="button" key={option.ref} onClick={() => chooseDestination(option)}><strong>{option.label}</strong>{option.secondary ? <small>{option.secondary}</small> : null}</button>)}</div> : null}
          {deliveryMethod !== "courier" && !cityRef ? <small>Вкажіть номер або повну адресу точки отримання.</small> : null}
        </label>

        <fieldset className="choice-group choice-group--payment">
          <legend>Оплата</legend>
          <label className={paymentMethod === "transfer" ? "is-active" : ""}><input type="radio" name="paymentMethod" checked={paymentMethod === "transfer"} onChange={() => setPaymentMethod("transfer")} /><span><Check aria-hidden size={15} /> Переказ після підтвердження</span><small>Реквізити для оплати надійдуть після підтвердження замовлення.</small></label>
          <label className={paymentMethod === "cash_on_delivery" ? "is-active" : ""}><input type="radio" name="paymentMethod" checked={paymentMethod === "cash_on_delivery"} onChange={() => setPaymentMethod("cash_on_delivery")} /><span><Check aria-hidden size={15} /> Післяплата</span><small>Оплата під час отримання.</small></label>
        </fieldset>

        <label className="form-field"><span>Коментар <small>(необовʼязково)</small></span><textarea name="comment" rows={4} maxLength={1200} placeholder="Колір, побажання або уточнення до замовлення" /></label>

        {error ? <div className="checkout-error" role="alert">{error}</div> : null}
        <button className="accent-pill accent-pill--large checkout-submit" type="submit" disabled={isSubmitting}>
          {isSubmitting ? "Оформлюємо…" : `Оформити на ${formatPrice(promo?.total ?? total)}`}
        </button>
        <div className="checkout-next-steps" aria-label="Що відбудеться після оформлення">
          <strong>Що буде далі</strong>
          <ul>
            <li><Check aria-hidden size={14} /> Ми підтвердимо деталі замовлення в Telegram.</li>
            <li><Check aria-hidden size={14} /> {paymentMethod === "transfer" ? "Реквізити для переказу надійдуть після підтвердження." : "Післяплата сплачується під час отримання."}</li>
            <li><Check aria-hidden size={14} /> Доставку Нова пошта розраховує окремо за чинними тарифами.</li>
          </ul>
        </div>
        <p className="checkout-consent">Після оформлення ви побачите номер і статус замовлення.</p>
      </section>
    </form>
  );
}
