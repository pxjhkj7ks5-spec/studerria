"use client";

import { MagnifyingGlass } from "@phosphor-icons/react";
import { trackPlausible } from "@/lib/analytics";

type CatalogFiltersProps = {
  action: string;
  categories: Array<{ id: number; name: string; slug: string }>;
  categorySlug: string;
  query: string;
  sort: string;
  purpose: string;
  compatibility: string;
  purposes: string[];
  compatibilities: string[];
};

export function CatalogFilters({
  action,
  categories,
  categorySlug,
  query,
  sort,
  purpose,
  compatibility,
  purposes,
  compatibilities,
}: CatalogFiltersProps) {
  return (
    <form
      action={action}
      className="catalog-controls"
      onSubmit={(event) => {
        const formData = new FormData(event.currentTarget);
        const category = String(formData.get("category") ?? "").trim();

        trackPlausible("Catalog Filter", {
          location: "catalog-controls",
          category: category || "all",
        });
      }}
    >
      <label className="catalog-search">
        <MagnifyingGlass aria-hidden size={20} />
        <span className="sr-only">Пошук по каталогу</span>
        <input
          name="q"
          defaultValue={query}
          placeholder="Що шукаєте?"
          autoComplete="off"
        />
      </label>

      <label className="catalog-select">
        <span className="sr-only">Категорія</span>
        <select name="category" defaultValue={categorySlug}>
          <option value="">Усі категорії</option>
          {categories.map((category) => (
            <option key={category.id} value={category.slug}>
              {category.name}
            </option>
          ))}
        </select>
      </label>

      {purposes.length ? (
        <label className="catalog-select catalog-select--facet">
          <span className="sr-only">Призначення</span>
          <select name="purpose" defaultValue={purpose}>
            <option value="">Усі призначення</option>
            {purposes.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
      ) : null}

      {compatibilities.length ? (
        <label className="catalog-select catalog-select--facet">
          <span className="sr-only">Сумісність</span>
          <select name="compatibility" defaultValue={compatibility}>
            <option value="">Уся сумісність</option>
            {compatibilities.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
        </label>
      ) : null}

      <label className="catalog-select catalog-select--sort">
        <span className="sr-only">Сортування</span>
        <select name="sort" defaultValue={sort}>
          <option value="recommended">Рекомендовані</option>
          <option value="newest">Спочатку нові</option>
          <option value="price-asc">Ціна: від нижчої</option>
          <option value="price-desc">Ціна: від вищої</option>
        </select>
      </label>

      <button className="accent-pill" type="submit">
        Знайти
      </button>
    </form>
  );
}
