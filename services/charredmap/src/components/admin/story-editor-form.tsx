"use client";

import Link from "next/link";
import { useActionState, useDeferredValue, useState } from "react";
import { deleteStoryAction, saveStoryAction, type ActionState } from "@/app/actions/admin";
import { SubmitButton } from "@/components/admin/submit-button";
import { withBasePath } from "@/lib/base-path";
import { normalizeCitySearchValue } from "@/lib/city-catalog";
import {
  buildCityLookupOptions,
  getCitySuggestions,
  type CityLookupCity,
} from "@/lib/city-lookup";
import type { OccupationStatus, PublicationStatus } from "@/lib/constants";

type EditableStory = {
  id: string;
  title: string;
  body: string;
  coverImageUrl: string | null;
  publicationStatus: PublicationStatus;
  submitterName: string | null;
  submitterContact: string | null;
  city: CityLookupCity;
};

type StoryEditorFormProps = {
  adminPath: string;
  cities: CityLookupCity[];
  story?: EditableStory | null;
};

const initialState: ActionState = {};

export function StoryEditorForm({
  adminPath,
  cities,
  story,
}: StoryEditorFormProps) {
  const [state, formAction] = useActionState(saveStoryAction, initialState);
  const [selectedCityId, setSelectedCityId] = useState(story?.city.id ?? "");
  const [selectedLookupKey, setSelectedLookupKey] = useState<string | null>(
    story?.city ? `existing:${story.city.id}` : null,
  );
  const [cityLookupOpen, setCityLookupOpen] = useState(false);
  const [cityName, setCityName] = useState(story?.city.name ?? "");
  const [oblast, setOblast] = useState(story?.city.oblast ?? "");
  const [lat, setLat] = useState(String(story?.city.lat ?? 49));
  const [lng, setLng] = useState(String(story?.city.lng ?? 32));
  const [occupationStatus, setOccupationStatus] = useState<OccupationStatus>(
    story?.city.occupationStatus ?? "deoccupied",
  );
  const [publicationStatus, setPublicationStatus] = useState<PublicationStatus>(
    story?.publicationStatus ?? "draft",
  );
  const deferredCityName = useDeferredValue(cityName);
  const cityLookupOptions = buildCityLookupOptions(cities);
  const citySuggestions = getCitySuggestions(deferredCityName, cityLookupOptions);
  const selectedLookup =
    selectedLookupKey
      ? cityLookupOptions.find((entry) => entry.key === selectedLookupKey) ?? null
      : null;
  const hasSubmitterInfo = Boolean(story?.submitterName || story?.submitterContact);
  const isModerationStory =
    story?.publicationStatus === "submitted" || hasSubmitterInfo;
  const editorEyebrow = story
    ? isModerationStory
      ? "Модерація"
      : "Редагування"
    : "Нова історія";
  const editorTitle = story
    ? isModerationStory
      ? "Перевірити публічне подання"
      : "Оновити матеріал"
    : "Додати матеріал на мапу";
  const editorDescription = story
    ? isModerationStory
      ? "Тут редактор бачить автора, контакт, текст і місто, а далі вирішує: лишити в черзі, перевести в чернетку або публікувати."
      : "Тут редактор коригує місто, текст, статус і вирішує, що піде в публічний шар."
    : "Окремий ручний редактор для внутрішніх матеріалів без прив’язки до публічної черги.";

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
    <div className="space-y-4">
      <form
        action={formAction}
        encType="multipart/form-data"
        className="glass-panel rounded-[32px] p-5 md:p-7"
      >
        <input type="hidden" name="storyId" value={story?.id ?? ""} />
        <input type="hidden" name="cityMode" value={selectedCityId ? "existing" : "new"} />
        <input type="hidden" name="cityId" value={selectedCityId} />
        <input type="hidden" name="publicationStatus" value={publicationStatus} />

        <div className="flex flex-col gap-4 border-b border-white/10 pb-6 md:flex-row md:items-end md:justify-between">
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-[0.28em] text-[--accent-orange]">
              {editorEyebrow}
            </p>
            <h1 className="font-display text-3xl text-white md:text-4xl">
              {editorTitle}
            </h1>
            <p className="max-w-2xl text-sm leading-6 text-white/72">
              {editorDescription}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => setPublicationStatus("submitted")}
              className={`rounded-full px-4 py-2 text-sm transition ${
                publicationStatus === "submitted"
                  ? "bg-[rgba(255,132,56,0.16)] text-[--accent-ember]"
                  : "border border-white/10 text-[--muted] hover:border-[--accent-orange]/40 hover:text-white"
              }`}
            >
              На модерації
            </button>
            <button
              type="button"
              onClick={() => setPublicationStatus("draft")}
              className={`rounded-full px-4 py-2 text-sm transition ${
                publicationStatus === "draft"
                  ? "bg-white/12 text-white"
                  : "border border-white/10 text-[--muted] hover:border-white/30 hover:text-white"
              }`}
            >
              Чернетка
            </button>
            <button
              type="button"
              onClick={() => setPublicationStatus("published")}
              className={`rounded-full px-4 py-2 text-sm transition ${
                publicationStatus === "published"
                  ? "bg-[--accent-orange] text-black"
                  : "border border-white/10 text-[--muted] hover:border-[--accent-orange]/55 hover:text-white"
              }`}
            >
              Публікація
            </button>
          </div>
        </div>

        <div className="mt-6 grid gap-6 xl:grid-cols-[1.35fr_0.95fr]">
          <section className="space-y-5">
            <label className="block space-y-2">
              <span className="text-sm text-[--muted]">Заголовок</span>
              <input
                name="title"
                defaultValue={story?.title ?? ""}
                required
                maxLength={140}
                className="w-full rounded-[22px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
              />
            </label>

            <label className="block space-y-2">
              <span className="text-sm text-[--muted]">Текст історії</span>
              <textarea
                name="body"
                defaultValue={story?.body ?? ""}
                required
                rows={14}
                maxLength={20000}
                className="min-h-[340px] w-full rounded-[28px] border border-white/10 bg-black/30 px-4 py-4 text-white outline-none transition focus:border-[--accent-orange]/60"
              />
            </label>

            <label className="block space-y-2">
              <span className="text-sm text-[--muted]">Cover photo</span>
              <input
                name="coverImage"
                type="file"
                accept="image/*"
                className="block w-full rounded-[22px] border border-dashed border-white/12 bg-black/25 px-4 py-4 text-sm text-[--muted] file:mr-4 file:rounded-full file:border-0 file:bg-white/10 file:px-4 file:py-2 file:text-white"
              />
            </label>

            {story?.coverImageUrl ? (
              <div className="overflow-hidden rounded-[24px] border border-white/8 bg-white/[0.03]">
                <img
                  src={withBasePath(story.coverImageUrl)}
                  alt={story.title}
                  className="h-52 w-full object-cover"
                />
              </div>
            ) : null}
          </section>

          <section className="space-y-5">
            {hasSubmitterInfo ? (
              <div className="rounded-[28px] border border-[--accent-orange]/18 bg-[rgba(255,132,56,0.08)] p-4">
                <p className="text-xs uppercase tracking-[0.24em] text-[--accent-orange]">
                  Надійшло з публічної форми
                </p>
                <div className="mt-4 grid gap-4 md:grid-cols-2">
                  <div>
                    <p className="text-[11px] uppercase tracking-[0.18em] text-white/46">
                      Автор
                    </p>
                    <p className="mt-2 text-sm leading-6 text-white">
                      {story?.submitterName ?? "Не вказано"}
                    </p>
                  </div>
                  <div>
                    <p className="text-[11px] uppercase tracking-[0.18em] text-white/46">
                      Контакт
                    </p>
                    <p className="mt-2 break-words text-sm leading-6 text-white">
                      {story?.submitterContact ?? "Не вказано"}
                    </p>
                  </div>
                </div>
              </div>
            ) : null}

            <div className="rounded-[28px] border border-white/8 bg-white/[0.03] p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="space-y-2">
                  <p className="text-xs uppercase tracking-[0.24em] text-[--muted]">
                    Прив&apos;язка міста
                  </p>
                  <p className="text-sm leading-6 text-white/72">
                    Почніть вводити назву міста, наприклад Київ або Авдіївку, і виберіть підказку.
                  </p>
                </div>
                {selectedLookup ? (
                  <button
                    type="button"
                    onClick={clearLinkedCity}
                    className="rounded-full border border-white/10 px-3 py-2 text-xs uppercase tracking-[0.18em] text-[--muted] transition hover:border-white/30 hover:text-white"
                  >
                    Очистити вибір
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
                        Нічого не знайдено. Можна продовжити вручну і створити нове місто.
                      </div>
                    )}
                  </div>
                ) : null}
              </div>

              {selectedLookup ? (
                <p className="mt-3 text-xs leading-5 text-[--muted]">
                  {selectedLookup.source === "existing"
                    ? "Вибрано існуючий запис міста з бази. Якщо збережете форму, зміни в полях міста оновлять саме цей запис."
                    : "Поля заповнено з локального каталогу міст України. Дані можна скоригувати вручну перед збереженням."}
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

            {state.error ? (
              <p className="rounded-[24px] border border-[--accent-red]/35 bg-[rgba(218,59,59,0.12)] px-4 py-4 text-sm text-[#ffc8c8]">
                {state.error}
              </p>
            ) : null}

            <div className="flex flex-wrap items-center gap-3 pt-2">
              <SubmitButton>Зберегти історію</SubmitButton>
              <Link
                href={`/${adminPath}/stories`}
                className="rounded-full border border-white/10 px-5 py-3 text-sm text-[--muted] transition hover:border-white/30 hover:text-white"
              >
                Повернутись до списку
              </Link>
            </div>
          </section>
        </div>
      </form>

      {story ? (
        <form
          action={deleteStoryAction}
          className="glass-panel flex flex-col gap-4 rounded-[28px] p-5 md:flex-row md:items-center md:justify-between"
        >
          <input type="hidden" name="storyId" value={story.id} />
          <div className="space-y-2">
            <p className="text-xs uppercase tracking-[0.24em] text-[--accent-red]">
              Небезпечна дія
            </p>
            <p className="text-sm leading-6 text-white/72">
              Видалення прибере матеріал з адмінки і з публічного шару. Дію не можна відкотити з
              інтерфейсу.
            </p>
          </div>
          <button
            type="submit"
            onClick={(event) => {
              if (!window.confirm("Видалити цю історію без можливості відновлення?")) {
                event.preventDefault();
              }
            }}
            className="rounded-full border border-[--accent-red]/35 bg-[rgba(218,59,59,0.12)] px-5 py-3 text-sm font-semibold text-[#ffc8c8] transition hover:border-[--accent-red]/55 hover:bg-[rgba(218,59,59,0.18)]"
          >
            Видалити історію
          </button>
        </form>
      ) : null}
    </div>
  );
}
