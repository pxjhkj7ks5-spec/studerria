"use client";

import Link from "next/link";
import { useActionState, useEffect, useState } from "react";
import { withBasePath } from "@/lib/base-path";
import type { OccupationStatus, PublicationStatus } from "@/lib/constants";
import { saveStoryAction } from "@/app/actions/admin";
import { SubmitButton } from "@/components/admin/submit-button";

type CityOption = {
  id: string;
  name: string;
  slug: string;
  oblast: string;
  lat: number;
  lng: number;
  occupationStatus: OccupationStatus;
};

type EditableStory = {
  id: string;
  title: string;
  body: string;
  coverImageUrl: string | null;
  publicationStatus: PublicationStatus;
  city: CityOption;
};

type StoryEditorFormProps = {
  adminPath: string;
  cities: CityOption[];
  story?: EditableStory | null;
};

const initialState = {};

export function StoryEditorForm({
  adminPath,
  cities,
  story,
}: StoryEditorFormProps) {
  const [state, formAction] = useActionState(saveStoryAction, initialState);
  const [cityMode, setCityMode] = useState<"existing" | "new">(
    story?.city ? "existing" : cities.length ? "existing" : "new",
  );
  const [selectedCityId, setSelectedCityId] = useState(story?.city.id ?? cities[0]?.id ?? "");
  const [cityName, setCityName] = useState(story?.city.name ?? cities[0]?.name ?? "");
  const [oblast, setOblast] = useState(story?.city.oblast ?? cities[0]?.oblast ?? "");
  const [lat, setLat] = useState(String(story?.city.lat ?? cities[0]?.lat ?? 49.0));
  const [lng, setLng] = useState(String(story?.city.lng ?? cities[0]?.lng ?? 32.0));
  const [occupationStatus, setOccupationStatus] = useState<OccupationStatus>(
    story?.city.occupationStatus ?? cities[0]?.occupationStatus ?? "deoccupied",
  );
  const [publicationStatus, setPublicationStatus] = useState<PublicationStatus>(
    story?.publicationStatus ?? "draft",
  );

  useEffect(() => {
    if (cityMode !== "existing" || !selectedCityId) {
      return;
    }

    const selectedCity = cities.find((entry) => entry.id === selectedCityId);

    if (!selectedCity) {
      return;
    }

    setCityName(selectedCity.name);
    setOblast(selectedCity.oblast);
    setLat(String(selectedCity.lat));
    setLng(String(selectedCity.lng));
    setOccupationStatus(selectedCity.occupationStatus);
  }, [cities, cityMode, selectedCityId]);

  return (
    <form
      action={formAction}
      encType="multipart/form-data"
      className="glass-panel rounded-[32px] p-5 md:p-7"
    >
      <input type="hidden" name="storyId" value={story?.id ?? ""} />
      <input type="hidden" name="cityMode" value={cityMode} />
      <input type="hidden" name="cityId" value={cityMode === "existing" ? selectedCityId : ""} />
      <input type="hidden" name="publicationStatus" value={publicationStatus} />

      <div className="flex flex-col gap-4 border-b border-white/10 pb-6 md:flex-row md:items-end md:justify-between">
        <div className="space-y-2">
          <p className="text-xs uppercase tracking-[0.28em] text-[--accent-orange]">
            {story ? "Редагування" : "Нова історія"}
          </p>
          <h1 className="font-display text-3xl text-white md:text-4xl">
            {story ? "Оновити матеріал" : "Додати матеріал на мапу"}
          </h1>
        </div>
        <div className="flex flex-wrap gap-2">
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
          <div className="rounded-[28px] border border-white/8 bg-white/[0.03] p-4">
            <p className="text-xs uppercase tracking-[0.24em] text-[--muted]">
              Прив&apos;язка міста
            </p>
            <div className="mt-4 flex gap-2">
              <button
                type="button"
                onClick={() => setCityMode("existing")}
                className={`rounded-full px-4 py-2 text-sm transition ${
                  cityMode === "existing"
                    ? "bg-white/12 text-white"
                    : "border border-white/10 text-[--muted] hover:border-white/25 hover:text-white"
                }`}
              >
                Існуюче
              </button>
              <button
                type="button"
                onClick={() => {
                  setCityMode("new");
                  setSelectedCityId("");
                }}
                className={`rounded-full px-4 py-2 text-sm transition ${
                  cityMode === "new"
                    ? "bg-white/12 text-white"
                    : "border border-white/10 text-[--muted] hover:border-white/25 hover:text-white"
                }`}
              >
                Нове місто
              </button>
            </div>

            {cityMode === "existing" ? (
              <label className="mt-4 block space-y-2">
                <span className="text-sm text-[--muted]">Оберіть місто</span>
                <select
                  value={selectedCityId}
                  onChange={(event) => setSelectedCityId(event.target.value)}
                  className="w-full rounded-[18px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
                >
                  <option value="">Оберіть зі списку</option>
                  {cities.map((city) => (
                    <option key={city.id} value={city.id}>
                      {city.name} • {city.oblast}
                    </option>
                  ))}
                </select>
              </label>
            ) : null}
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <label className="space-y-2">
              <span className="text-sm text-[--muted]">Місто</span>
              <input
                name="cityName"
                value={cityName}
                onChange={(event) => setCityName(event.target.value)}
                required
                className="w-full rounded-[18px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
              />
            </label>
            <label className="space-y-2">
              <span className="text-sm text-[--muted]">Область</span>
              <input
                name="oblast"
                value={oblast}
                onChange={(event) => setOblast(event.target.value)}
                required
                className="w-full rounded-[18px] border border-white/10 bg-black/30 px-4 py-3 text-white outline-none transition focus:border-[--accent-orange]/60"
              />
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
  );
}
