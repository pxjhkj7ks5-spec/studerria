"use client";
import { useEffect, useRef, useState } from "react";
import { withBasePath } from "@/lib/base-path";
import { getAnalyticsSessionId, trackAnalytics } from "@/lib/analytics";

type Props = { initialMode: "file" | "model"; productSlug: string; productTitle: string; telegramUrl: string };
export function CustomRequestForm({ initialMode, productSlug, productTitle, telegramUrl }: Props) {
  const [mode, setMode] = useState(initialMode);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [fileNames, setFileNames] = useState<string[]>([]);
  const [result, setResult] = useState<{ publicId: string; description: string; quantity: string } | null>(null);
  const key = useRef("");
  const started = useRef(false);
  const opened = useRef(false);
  const submitting = useRef(false);
  const successRef = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    key.current = crypto.randomUUID();
    if (!opened.current) { opened.current = true; trackAnalytics("Custom Request Open", { intent:"custom", location:initialMode }); }
  }, [initialMode]);
  useEffect(() => { if (result) successRef.current?.focus(); }, [result]);
  function start() {
    if (!started.current) { started.current = true; trackAnalytics("Custom Request Start", { intent:"custom",location:mode }); }
  }
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting.current) return;
    submitting.current = true;
    setPending(true); setError(""); start();
    const data = new FormData(event.currentTarget);
    data.set("mode",mode); data.set("submissionKey", key.current || (key.current = crypto.randomUUID()));
    data.set("analyticsSessionId", getAnalyticsSessionId());
    try {
      const files = data.getAll("files").filter((file): file is File => file instanceof File && file.size > 0);
      if (files.length > 4 || files.reduce((sum,file) => sum+file.size,0) > 10 * 1024 * 1024) throw new Error("Додайте до чотирьох файлів загальним розміром до 10 МБ.");
      if (mode === "file" && !files.length && !String(data.get("modelUrl") ?? "").trim()) throw new Error("Додайте файл або посилання на модель.");
      const response = await fetch(withBasePath("/api/custom-requests"), { method:"POST",body:data });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Не вдалося надіслати заявку. Спробуйте ще раз.");
      setResult({ publicId:payload.publicId,description:String(data.get("description")),quantity:String(data.get("quantity")) });
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Не вдалося надіслати заявку."); }
    finally { submitting.current = false; setPending(false); }
  }
  if (result) return <section className="custom-success" aria-live="polite"><p className="eyebrow">Заявку збережено</p><h2 ref={successRef} tabIndex={-1}>Дякуємо! Заявка {result.publicId}</h2><p>{mode === "file" ? "Друк файлу" : "Моделювання"} · {result.quantity} шт.</p><p className="custom-summary">{result.description}</p>{fileNames.length ? <p>Вкладення: {fileNames.join(", ")}</p> : null}<p>Власник уточнить задачу, погодить ціну та термін у Telegram. Виготовлення починаємо після погодження.</p><a className="ghost-pill" href={telegramUrl} target="_blank" rel="noreferrer">Зв’язатися в Telegram</a><a className="accent-pill" href={withBasePath("/catalog")}>До каталогу</a></section>;
  return <form className="custom-form" onSubmit={submit} onChange={start} aria-describedby={error ? "custom-error" : undefined}>
    <fieldset disabled={pending}>
      <legend>Що потрібно виготовити?</legend>
      <div className="custom-mode"><label className={mode === "file" ? "is-active" : ""}><input type="radio" name="modeChoice" value="file" checked={mode === "file"} onChange={() => setMode("file")} />Маю файл</label><label className={mode === "model" ? "is-active" : ""}><input type="radio" name="modeChoice" value="model" checked={mode === "model"} onChange={() => setMode("model")} />Потрібна 3D-модель</label></div>
      <p>{mode === "file" ? "Додайте готову модель або посилання. Для більших файлів скористайтеся посиланням." : "Опишіть ідею. Фото, ескіз або приклад допоможуть оцінити моделювання з нуля."}</p>
      {productTitle ? <p>На основі виробу: {productTitle}</p> : null}
      <input type="hidden" name="productSlug" value={productSlug} />
      <div className="custom-fields">
        <label className="form-field"><span>Ім’я</span><input name="name" required minLength={2} maxLength={80} autoComplete="given-name" /></label>
        <label className="form-field"><span>Telegram</span><input name="telegramContact" required maxLength={33} placeholder="@username або номер" aria-describedby="custom-contact-note" /><small id="custom-contact-note">Для погодження ціни, терміну й деталей.</small></label>
        <label className="form-field custom-fields__wide"><span>Опис задачі</span><textarea name="description" required minLength={10} maxLength={3000} rows={5} defaultValue={productTitle ? `Хочу адаптувати ${productTitle}: ` : ""} placeholder="Що потрібно, для чого й які є побажання?" /></label>
        <label className="form-field"><span>Кількість, шт.</span><input name="quantity" type="number" min={1} max={1000} step={1} defaultValue={1} required /></label>
        <label className="form-field"><span>Телефон (необов’язково)</span><input name="phone" type="tel" autoComplete="tel" maxLength={30} /></label>
        <label className="form-field"><span>Розміри (необов’язково)</span><input name="dimensions" maxLength={200} placeholder="Наприклад: 100 × 50 × 20 мм" /></label>
        <label className="form-field"><span>Бажаний строк (необов’язково)</span><input name="desiredDate" maxLength={100} placeholder="Коли потрібен готовий виріб?" /></label>
        <label className="form-field"><span>Бюджет, грн (необов’язково)</span><input name="budget" type="number" min={0} max={10000000} step={1} /></label>
        <label className="form-field"><span>Посилання на модель або приклад</span><input name="modelUrl" type="url" maxLength={1000} placeholder="https://…" /></label>
        <label className="form-field custom-fields__wide custom-upload"><span>Файли та фото</span><small id="custom-upload-note">STL, 3MF, OBJ, JPG, PNG, WebP, PDF · до 4 файлів · до 10 МБ сумарно. Надсилайте файли, які маєте право використовувати.</small><input type="file" name="files" multiple accept=".stl,.3mf,.obj,.jpg,.jpeg,.png,.webp,.pdf" aria-describedby="custom-upload-note" onChange={(event) => setFileNames(Array.from(event.target.files ?? []).map((file) => file.name))} />{fileNames.length ? <small>{fileNames.join(", ")}</small> : null}</label>
      </div>
      <div className="custom-honeypot" aria-hidden="true"><label>Website<input name="website" tabIndex={-1} autoComplete="off" /></label></div>
      <p>Ціну та можливість виготовлення визначимо після оцінки. Надсилаючи заявку, ви передаєте дані для її обробки згідно з <a href={withBasePath("/privacy")}>правилами конфіденційності</a>.</p>
      {error ? <p role="alert" id="custom-error" className="custom-error">{error}</p> : null}
      <div className="custom-actions"><button className="accent-pill accent-pill--large" type="submit">{pending ? "Зберігаємо…" : "Надіслати заявку"}</button><a className="ghost-pill" href={telegramUrl} target="_blank" rel="noreferrer">Або написати в Telegram</a></div>
    </fieldset>
  </form>;
}
