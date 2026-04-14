import { cityCatalog, normalizeCitySearchValue, scoreCitySearchMatch } from "@/lib/city-catalog";
import type { OccupationStatus } from "@/lib/constants";

export type CityLookupCity = {
  id: string;
  name: string;
  slug: string;
  oblast: string;
  lat: number;
  lng: number;
  occupationStatus: OccupationStatus;
};

export type CityLookupOption = {
  key: string;
  source: "existing" | "catalog";
  id?: string;
  name: string;
  slug: string;
  oblast: string;
  lat: number;
  lng: number;
  occupationStatus?: OccupationStatus;
  aliases?: string[];
};

export function buildCityLookupOptions(cities: CityLookupCity[]): CityLookupOption[] {
  const seen = new Set<string>();
  const options: CityLookupOption[] = [];

  for (const city of cities) {
    const signature = normalizeCitySearchValue(`${city.name} ${city.oblast}`);
    seen.add(signature);
    options.push({
      key: `existing:${city.id}`,
      source: "existing",
      id: city.id,
      name: city.name,
      slug: city.slug,
      oblast: city.oblast,
      lat: city.lat,
      lng: city.lng,
      occupationStatus: city.occupationStatus,
    });
  }

  for (const city of cityCatalog) {
    const signature = normalizeCitySearchValue(`${city.name} ${city.oblast}`);

    if (seen.has(signature)) {
      continue;
    }

    options.push({
      key: `catalog:${city.slug}`,
      source: "catalog",
      name: city.name,
      slug: city.slug,
      oblast: city.oblast,
      lat: city.lat,
      lng: city.lng,
      aliases: city.aliases,
    });
  }

  return options;
}

export function getCitySuggestions(query: string, options: CityLookupOption[]) {
  const normalizedQuery = normalizeCitySearchValue(query);

  if (normalizedQuery.length < 2) {
    return [];
  }

  return options
    .map((option) => ({
      option,
      score: scoreCitySearchMatch(normalizedQuery, option),
    }))
    .filter((entry) => entry.score > 0)
    .sort((left, right) => {
      if (right.score !== left.score) {
        return right.score - left.score;
      }

      if (left.option.source !== right.option.source) {
        return left.option.source === "existing" ? -1 : 1;
      }

      return left.option.name.localeCompare(right.option.name, "uk-UA");
    })
    .slice(0, 8)
    .map((entry) => entry.option);
}
