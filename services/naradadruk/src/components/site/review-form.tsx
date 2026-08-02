"use client";

import { useState, type FormEvent } from "react";
import { withBasePath } from "@/lib/base-path";

type ReviewOrderContext = {
  publicId: string;
  number: string;
  alreadySubmitted: boolean;
};

export function ReviewForm({
  orderContext,
  invalidOrderLink = false,
}: {
  orderContext?: ReviewOrderContext | null;
  invalidOrderLink?: boolean;
}) {
  const [anonymous, setAnonymous] = useState(false);
  const [state, setState] = useState<{ kind: "idle" | "sending" | "success" | "error"; message?: string }>({ kind: "idle" });

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    data.set("isAnonymous", anonymous ? "true" : "false");
    if (orderContext?.publicId) data.set("orderPublicId", orderContext.publicId);
    setState({ kind: "sending" });
    try {
      const response = await fetch(withBasePath("/api/reviews"), { method: "POST", body: data });
      const result = await response.json().catch(() => ({})) as { error?: string };
      if (!response.ok) throw new Error(result.error || "Не вдалося надіслати відгук.");
      form.reset();
      setAnonymous(false);
      setState({ kind: "success", message: "Дякуємо! Відгук надіслано на модерацію. Після схвалення він з’явиться на сайті." });
    } catch (error) {
      setState({ kind: "error", message: error instanceof Error ? error.message : "Не вдалося надіслати відгук." });
    }
  }

  return (
    <form className="review-form" onSubmit={submit}>
      <div className="review-form__heading">
        <p className="eyebrow">Поділіться досвідом</p>
        <h2>Залишити відгук</h2>
        <p>Усі відгуки спочатку перевіряються. Можна додати до 4 фото.</p>
      </div>

      {orderContext ? (
        <div className={orderContext.alreadySubmitted ? "status-message" : "review-order-context"}>
          <strong>Замовлення #{orderContext.number}</strong>
          <span>
            {orderContext.alreadySubmitted
              ? "Відгук за цим замовленням уже надіслано. Дякуємо!"
              : "Ваш відгук буде позначено як підтверджене замовлення."}
          </span>
        </div>
      ) : invalidOrderLink ? (
        <div className="status-message status-message--error" role="alert">
          Посилання на замовлення недійсне. Попросіть майстерню надіслати нове.
        </div>
      ) : null}

      <label className="form-field">
        <span>Ім’я <small>(необов’язково)</small></span>
        <input name="displayName" maxLength={60} disabled={anonymous} placeholder="Як до вас звертатися" />
      </label>
      <label className="review-anonymous">
        <input type="checkbox" checked={anonymous} onChange={(event) => setAnonymous(event.target.checked)} />
        <span>Опублікувати анонімно</span>
      </label>
      <label className="form-field">
        <span>Ваш відгук</span>
        <textarea name="body" minLength={20} maxLength={1500} rows={7} required placeholder="Розкажіть про виріб, якість або досвід замовлення" />
        <small>Від 20 до 1500 символів.</small>
      </label>
      <label className="form-field">
        <span>Фото <small>(необов’язково)</small></span>
        <input name="photos" type="file" accept="image/jpeg,image/png,image/webp" multiple />
        <small>До 4 фото, максимум 5 MB кожне і 12 MB разом.</small>
      </label>
      <label className="review-honeypot" aria-hidden>
        Website<input name="website" tabIndex={-1} autoComplete="off" />
      </label>

      {state.kind === "success" ? <div className="status-message status-message--ok" role="status">{state.message}</div> : null}
      {state.kind === "error" ? <div className="status-message status-message--error" role="alert">{state.message}</div> : null}
      <button className="accent-pill accent-pill--large" type="submit" disabled={state.kind === "sending" || orderContext?.alreadySubmitted || invalidOrderLink}>
        {state.kind === "sending" ? "Надсилаємо…" : "Надіслати відгук"}
      </button>
    </form>
  );
}
