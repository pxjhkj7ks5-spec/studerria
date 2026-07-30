"use client";

import { MagnifyingGlass } from "@phosphor-icons/react";
import { trackPlausible } from "@/lib/analytics";

type CatalogFiltersProps = {
  action: string;
  categories: Array<{ id: number; name: string; slug: string }>;
  categorySlug: string;
  query: string;
};

export function CatalogFilters({
  action,
  categories,
  categorySlug,
  query,
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

      <button className="accent-pill" type="submit">
        Знайти
      </button>
    </form>
  );
}
