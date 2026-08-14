const novaPoshtaEndpoint = "https://api.novaposhta.ua/v2.0/json/";

export type NovaPoshtaOption = {
  ref: string;
  label: string;
  secondary: string;
};

const popularCityNames = [
  "Київ",
  "Дніпро",
  "Харків",
  "Одеса",
  "Львів",
  "Запоріжжя",
  "Вінниця",
  "Полтава",
];

const fallbackCities = [
  ...popularCityNames,
  "Черкаси",
  "Івано-Франківськ",
  "Тернопіль",
  "Ужгород",
];

let popularCitiesCache: { expiresAt: number; options: NovaPoshtaOption[] } | null = null;

function getApiKey() {
  return process.env.YKG_NOVA_POSHTA_API_KEY?.trim() || "";
}
async function callNovaPoshta<T>(modelName: string, calledMethod: string, methodProperties: Record<string, string>) {
  const apiKey = getApiKey();
  if (!apiKey) return null;

  const response = await fetch(novaPoshtaEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ apiKey, modelName, calledMethod, methodProperties }),
    cache: "no-store",
    signal: AbortSignal.timeout(8000),
  });

  if (!response.ok) throw new Error(`Nova Poshta HTTP ${response.status}`);
  const payload = (await response.json()) as { success?: boolean; data?: T[]; errors?: string[] };
  if (!payload.success) throw new Error(payload.errors?.join("; ") || "Nova Poshta API error");
  return payload.data ?? [];
}

async function getPopularCities() {
  if (!getApiKey()) return null;
  if (popularCitiesCache && popularCitiesCache.expiresAt > Date.now()) {
    return popularCitiesCache.options;
  }

  const results = await Promise.allSettled(
    popularCityNames.map((cityName) =>
      callNovaPoshta<{
        Ref: string;
        Description: string;
        AreaDescription?: string;
        SettlementTypeDescription?: string;
      }>("Address", "getCities", {
        FindByString: cityName,
        Limit: "5",
        Page: "1",
      }),
    ),
  );

  const options = results.flatMap((result, index) => {
    if (result.status !== "fulfilled" || !result.value) return [];
    const expectedName = popularCityNames[index].toLocaleLowerCase("uk-UA");
    const city =
      result.value.find((entry) => entry.Description.toLocaleLowerCase("uk-UA") === expectedName) ??
      result.value[0];
    return city
      ? [{
          ref: city.Ref,
          label: city.Description,
          secondary: [city.SettlementTypeDescription, city.AreaDescription].filter(Boolean).join(", "),
        }]
      : [];
  });

  if (options.length > 0) {
    popularCitiesCache = { expiresAt: Date.now() + 24 * 60 * 60 * 1000, options };
  }
  return options;
}

export async function searchCities(query: string) {
  const normalized = query.trim();
  if (!normalized) {
    const popularCities = await getPopularCities();
    if (popularCities && popularCities.length > 0) {
      return { configured: true, options: popularCities };
    }
    return {
      configured: false,
      options: popularCityNames.map((city) => ({ ref: "", label: city, secondary: "" })),
    };
  }

  const data = await callNovaPoshta<{
    Ref: string;
    Description: string;
    AreaDescription?: string;
    SettlementTypeDescription?: string;
  }>("Address", "getCities", {
    FindByString: normalized,
    Limit: "20",
    Page: "1",
  });

  if (data) {
    return {
      configured: true,
      options: data.map((city) => ({
        ref: city.Ref,
        label: city.Description,
        secondary: [city.SettlementTypeDescription, city.AreaDescription].filter(Boolean).join(", "),
      })),
    };
  }

  const needle = normalized.toLocaleLowerCase("uk-UA");
  return {
    configured: false,
    options: fallbackCities
      .filter((city) => !needle || city.toLocaleLowerCase("uk-UA").includes(needle))
      .slice(0, 8)
      .map((city) => ({ ref: "", label: city, secondary: "" })),
  };
}

export async function searchWarehouses(cityRef: string, query: string, method: "branch" | "parcel_locker") {
  if (!cityRef || !getApiKey()) return { configured: false, options: [] as NovaPoshtaOption[] };

  const data = await callNovaPoshta<{
    Ref: string;
    Description: string;
    ShortAddress?: string;
    CategoryOfWarehouse?: string;
    TypeOfWarehouse?: string;
  }>("AddressGeneral", "getWarehouses", {
    CityRef: cityRef,
    FindByString: query.trim(),
    Limit: "50",
    Page: "1",
  });

  const filtered = (data ?? []).filter((warehouse) => {
    const haystack = `${warehouse.CategoryOfWarehouse || ""} ${warehouse.Description || ""}`.toLocaleLowerCase("uk-UA");
    const isLocker = haystack.includes("поштомат") || haystack.includes("parcel locker");
    return method === "parcel_locker" ? isLocker : !isLocker;
  });

  return {
    configured: true,
    options: filtered.slice(0, 25).map((warehouse) => ({
      ref: warehouse.Ref,
      label: warehouse.Description,
      secondary: warehouse.ShortAddress || "",
    })),
  };
}
