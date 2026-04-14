"use client";

import Link from "next/link";
import { useActionState, useDeferredValue, useState } from "react";
import {
  submitStoryAction,
  type PublicSubmissionState,
} from "@/app/actions/public";
import { SubmitButton } from "@/components/admin/submit-button";
import {
  buildCityLookupOptions,
  getCitySuggestions,
  type CityLookupCity,
} from "@/lib/city-lookup";
import { normalizeCitySearchValue } from "@/lib/city-catalog";
import type { OccupationStatus } from "@/lib/constants";

type PublicStoryFormProps = {
  cities: CityLookupCity[];
};

const initialState: PublicSubmissionState = {};

export function PublicStoryForm({ cities }: PublicStoryFormProps) {
  const [state, formAction] = useActionState(submitStoryAction, initialState);
  const [selectedCityId, setSelectedCityId] = useState("");
  const [selectedLookupKey, setSelectedLookupKey] = useState<string | null>(null);
  const [cityLookupOpen, setCityLookupOpen] = useState(false);
  const [cityName, setCityName] = useState("");
  const [oblast, setOblast] = useState("");
  const [lat, setLat] = useState("49");
  const [lng, setLng] = useState("32");
  const [occupationStatus, setOccupationStatus] = useState<OccupationStatus>("deoccupied");
  const deferredCityName = useDeferredValue(cityName);
  const cityLookupOptions = buildCityLookupOptions(cities);
  const citySuggestions = getCitySuggestions(deferredCityName, cityLookupOptions);
  const selectedLookup =
    selectedLookupKey
      ? cityLookupOptions.find((entry) => entry.key === selectedLookupKey) ?? null
      : null;

  const clearLinkedCity = () => {
    setSelectedCityId("");
    setSelectedLookupKey(null);
  };

  const applyCitySuggestion = (option: (typeof citySuggestions)[number]) => {
    setCityName(option.name);
    setOblast(option.oblast);
    setLat(String(option.lat));
    setLng(String(option.lng));
    setSelectedLookupKey(option.key);
    setCityLookupOpen(false);

    if (option.source === "existing" && option.id) {
      setSelectedCityId(option.id);
      setOccupationStatus(option.occupationStatus ?? occupationStatus);
      return;
    }

    setSelectedCityId("");
  };

  return (
    <form action={formAction} className="glass-panel rounded-[34px] p-5 md:p-7">
      <input type="hidden" name="cityMode" value={selectedCityId ? "existing" : "new"} />
      <input type="hidden" name="cityId" value={selectedCityId} />

      <label className="sr-only" aria-hidden="true">
        Website
        <input name="website" tabIndex={-1} autoComplete="off" />
      </label>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(18rem,0.8fr)]">
        <section className="space-y-5">
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-[0.3em] text-[--accent-orange]">
              Публічна подача
            </p>
            <h1 className="font-display text-3xl leading-[0.96] text-white md:text-4xl">
              Надішліть історію, а редактор проведе її через модерацію.
            </h1>
            <p className="max-w-2xl text-sm leading-7 text-white/74">
              Публікація не з&apos;являється на мапі автоматично. Спершу матеріал потрапляє в
              окрему чергу модерації, де редактор перевіряє текст, місто і контекст.
            </p>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-[--muted]">Ваше ім&apos;я</span>
              <input
                name="submitterName"
                required
                maxLength={80}
                placeholder="Ім'я або псевдонім"
                className="w-full rounded-[20px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-[--muted]">Контакт</span>
              <input
                name="submitterContact"
                required
                maxLength={160}
                placeholder="email, Telegram або інший контакт"
                className="w-full rounded-[20px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
              />
            </label>
          </div>

          <label className="block space-y-2">
            <span className="text-sm text-[--muted]">Заголовок</span>
            <input
              name="title"
              required
              maxLength={140}
              placeholder="Короткий заголовок історії"
              className="w-full rounded-[20px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
            />
          </label>

          <div className="rounded-[28px] border border-white/8 bg-white/[0.03] p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="space-y-2">
                <p className="text-xs uppercase tracking-[0.24em] text-[--muted]">
                  Місто
                </p>
                <p className="text-sm leading-6 text-white/72">
                  Почніть вводити назву міста, наприклад Київ або Авдіївку, і виберіть запис зі
                  списку. Область і координати підтягнуться автоматично.
                </p>
              </div>
              {selectedLookup ? (
                <button
                  type="button"
                  onClick={clearLinkedCity}
                  className="rounded-full border border-white/10 px-3 py-2 text-xs uppercase tracking-[0.18em] text-[--muted] transition hover:border-white/30 hover:text-white"
                >
                  Очистити
                </button>
              ) : null}
            </div>

            <div className="relative mt-4">
              <label className="block space-y-2">
                <span className="text-sm text-[--muted]">Місто</span>
                <input
                  name="cityName"
                  value={cityName}
                  onChange={(event) => {
                    const nextValue = event.target.value;
                    setCityName(nextValue);
                    setCityLookupOpen(true);

                    if (
                      selectedLookup &&
                      normalizeCitySearchValue(nextValue) !==
                        normalizeCitySearchValue(selectedLookup.name)
                    ) {
                      clearLinkedCity();
                    }
                  }}
                  onFocus={() => setCityLookupOpen(true)}
                  onBlur={() => {
                    window.setTimeout(() => setCityLookupOpen(false), 120);
                  }}
                  autoComplete="off"
                  required
                  maxLength={80}
                  placeholder="Київ, Авдіївка, Ізюм..."
                  className="w-full rounded-[18px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
                />
              </label>

              {cityLookupOpen && normalizeCitySearchValue(deferredCityName).length >= 2 ? (
                <div className="absolute inset-x-0 top-[calc(100%+0.55rem)] z-30 overflow-hidden rounded-[24px] border border-white/10 bg-[rgba(7,9,12,0.94)] shadow-[0_30px_80px_rgba(0,0,0,0.4)] backdrop-blur-2xl">
                  {citySuggestions.length ? (
                    <div className="max-h-80 overflow-y-auto story-scrollbar p-2">
                      {citySuggestions.map((option) => (
                        <button
                          key={option.key}
                          type="button"
                          onMouseDown={(event) => event.preventDefault()}
                          onClick={() => applyCitySuggestion(option)}
                          className="flex w-full items-start justify-between gap-4 rounded-[18px] px-3 py-3 text-left transition hover:bg-white/[0.06]"
                        >
                          <div className="min-w-0">
                            <p className="text-sm text-white">{option.name}</p>
                            <p className="mt-1 text-xs uppercase tracking-[0.18em] text-[--muted]">
                              {option.oblast}
                            </p>
                          </div>
                          <span
                            className={`shrink-0 rounded-full px-2 py-1 text-[10px] uppercase tracking-[0.16em] ${
                              option.source === "existing"
                                ? "border border-[--accent-orange]/35 bg-[rgba(255,132,56,0.14)] text-[--accent-ember]"
                                : "border border-white/10 bg-white/[0.05] text-[--muted]"
                            }`}
                          >
                            {option.source === "existing" ? "Існуюче" : "Каталог"}
                          </span>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <div className="px-4 py-4 text-sm leading-6 text-[--muted]">
                      Підказки не знайшлися. Можна продовжити вручну і запропонувати новий запис
                      міста.
                    </div>
                  )}
                </div>
              ) : null}
            </div>

            {selectedLookup ? (
              <p className="mt-3 text-xs leading-5 text-[--muted]">
                {selectedLookup.source === "existing"
                  ? "Вибрано вже наявне місто. Публічна форма не змінює його запис, а тільки прив’язує до нього новий матеріал."
                  : "Дані взято з локального каталогу міст України. За потреби їх можна скоригувати перед відправкою."}
              </p>
            ) : null}
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-[--muted]">Область</span>
              <input
                name="oblast"
                value={oblast}
                onChange={(event) => setOblast(event.target.value)}
                required
                maxLength={80}
                className="w-full rounded-[18px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-[--muted]">Статус міста</span>
              <select
                name="occupationStatus"
                value={occupationStatus}
                onChange={(event) =>
                  setOccupationStatus(event.target.value as OccupationStatus)
                }
                className="w-full rounded-[18px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
              >
                <option value="occupied">Окуповане</option>
                <option value="deoccupied">Деокуповане</option>
              </select>
            </label>
            <label className="space-y-2">
              <span className="text-sm text-[--muted]">Широта</span>
              <input
                name="lat"
                type="number"
                step="0.0001"
                value={lat}
                onChange={(event) => setLat(event.target.value)}
                required
                className="w-full rounded-[18px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-[--muted]">Довгота</span>
              <input
                name="lng"
                type="number"
                step="0.0001"
                value={lng}
                onChange={(event) => setLng(event.target.value)}
                required
                className="w-full rounded-[18px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
              />
            </label>
          </div>

          <label className="block space-y-2">
            <span className="text-sm text-[--muted]">Текст історії</span>
            <textarea
              name="body"
              required
              rows={14}
              maxLength={20000}
              placeholder="Опишіть місто, контекст, подію та чому цю історію важливо зберегти."
              className="min-h-[320px] w-full rounded-[28px] border border-white/10 bg-black/30 px-4 py-4 text-white outline-none transition focus:border-[--accent-orange]/60"
            />
          </label>

          {state.error ? (
            <p className="rounded-[24px] border border-[--accent-red]/35 bg-[rgba(218,59,59,0.12)] px-4 py-4 text-sm text-[#ffc8c8]">
              {state.error}
            </p>
          ) : null}

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <SubmitButton pendingLabel="Надсилання...">Надіслати на модерацію</SubmitButton>
            <Link
              href="/"
              className="rounded-full border border-white/10 px-5 py-3 text-sm text-[--muted] transition hover:border-white/30 hover:text-white"
            >
              Повернутись на мапу
            </Link>
          </div>
        </section>

        <aside className="space-y-4">
          <div className="rounded-[30px] border border-white/8 bg-white/[0.04] p-5">
            <p className="text-xs uppercase tracking-[0.28em] text-[--accent-orange]">
              Як це працює
            </p>
            <div className="mt-4 space-y-4">
              <div className="border-t border-white/10 pt-4">
                <p className="text-sm font-semibold text-white">1. Ви надсилаєте історію</p>
                <p className="mt-2 text-sm leading-6 text-white/70">
                  Матеріал потрапляє в закриту чергу, а не одразу на карту.
                </p>
              </div>
              <div className="border-t border-white/10 pt-4">
                <p className="text-sm font-semibold text-white">2. Редактор перевіряє контекст</p>
                <p className="mt-2 text-sm leading-6 text-white/70">
                  Уточнюються місто, текст, формулювання й контакт для зворотного зв&apos;язку.
                </p>
              </div>
              <div className="border-t border-white/10 pt-4">
                <p className="text-sm font-semibold text-white">3. Лише після цього йде публікація</p>
                <p className="mt-2 text-sm leading-6 text-white/70">
                  На мапу виходять тільки відібрані та відмодеровані історії.
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-[30px] border border-white/8 bg-[rgba(255,132,56,0.08)] p-5">
            <p className="text-xs uppercase tracking-[0.28em] text-[--accent-orange]">
              Важливо
            </p>
            <ul className="mt-4 space-y-3 text-sm leading-6 text-white/78">
              <li>Без анонімного зображення чи файлів: тільки текст і прив&apos;язка до міста.</li>
              <li>Контакт бачить лише модератор усередині адмінки.</li>
              <li>Після відправки матеріал можна допрацювати вже через зворотний зв&apos;язок.</li>
            </ul>
          </div>
        </aside>
      </div>
    </form>
  );
}
