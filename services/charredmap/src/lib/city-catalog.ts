export type CityCatalogEntry = {
  name: string;
  slug: string;
  oblast: string;
  lat: number;
  lng: number;
  aliases?: string[];
};

export const cityCatalog: CityCatalogEntry[] = [
  { name: "Київ", slug: "kyiv", oblast: "місто Київ", lat: 50.4501, lng: 30.5234, aliases: ["києва", "києві", "kiev"] },
  { name: "Харків", slug: "kharkiv", oblast: "Харківська область", lat: 49.9935, lng: 36.2304, aliases: ["харкова"] },
  { name: "Одеса", slug: "odesa", oblast: "Одеська область", lat: 46.4825, lng: 30.7233, aliases: ["одесу", "odessa"] },
  { name: "Дніпро", slug: "dnipro", oblast: "Дніпропетровська область", lat: 48.4647, lng: 35.0462, aliases: ["дніпра", "днепр"] },
  { name: "Запоріжжя", slug: "zaporizhzhia", oblast: "Запорізька область", lat: 47.8388, lng: 35.1396, aliases: ["запоріжжя", "запоріжжю"] },
  { name: "Львів", slug: "lviv", oblast: "Львівська область", lat: 49.8397, lng: 24.0297, aliases: ["львова", "lvov"] },
  { name: "Миколаїв", slug: "mykolaiv", oblast: "Миколаївська область", lat: 46.975, lng: 31.9946, aliases: ["миколаєва", "nikolaev"] },
  { name: "Херсон", slug: "kherson", oblast: "Херсонська область", lat: 46.6354, lng: 32.6169 },
  { name: "Чернігів", slug: "chernihiv", oblast: "Чернігівська область", lat: 51.4982, lng: 31.2893 },
  { name: "Суми", slug: "sumy", oblast: "Сумська область", lat: 50.9077, lng: 34.7981, aliases: ["сум", "сумах"] },
  { name: "Полтава", slug: "poltava", oblast: "Полтавська область", lat: 49.5883, lng: 34.5514, aliases: ["полтаву"] },
  { name: "Вінниця", slug: "vinnytsia", oblast: "Вінницька область", lat: 49.2331, lng: 28.4682, aliases: ["вінницю"] },
  { name: "Житомир", slug: "zhytomyr", oblast: "Житомирська область", lat: 50.2547, lng: 28.6587 },
  { name: "Черкаси", slug: "cherkasy", oblast: "Черкаська область", lat: 49.4444, lng: 32.0598 },
  { name: "Рівне", slug: "rivne", oblast: "Рівненська область", lat: 50.6199, lng: 26.2516 },
  { name: "Луцьк", slug: "lutsk", oblast: "Волинська область", lat: 50.7472, lng: 25.3254 },
  { name: "Тернопіль", slug: "ternopil", oblast: "Тернопільська область", lat: 49.5535, lng: 25.5948 },
  { name: "Івано-Франківськ", slug: "ivano-frankivsk", oblast: "Івано-Франківська область", lat: 48.9226, lng: 24.7111, aliases: ["франківськ"] },
  { name: "Ужгород", slug: "uzhhorod", oblast: "Закарпатська область", lat: 48.6208, lng: 22.2879 },
  { name: "Чернівці", slug: "chernivtsi", oblast: "Чернівецька область", lat: 48.2915, lng: 25.9403 },
  { name: "Хмельницький", slug: "khmelnytskyi", oblast: "Хмельницька область", lat: 49.4216, lng: 26.9965 },
  { name: "Кропивницький", slug: "kropyvnytskyi", oblast: "Кіровоградська область", lat: 48.5079, lng: 32.2623 },
  { name: "Кривий Ріг", slug: "kryvyi-rih", oblast: "Дніпропетровська область", lat: 47.9105, lng: 33.3918, aliases: ["кривого рогу"] },
  { name: "Кременчук", slug: "kremenchuk", oblast: "Полтавська область", lat: 49.068, lng: 33.4204 },
  { name: "Кам'янське", slug: "kamianske", oblast: "Дніпропетровська область", lat: 48.508, lng: 34.613, aliases: ["каменское"] },
  { name: "Павлоград", slug: "pavlohrad", oblast: "Дніпропетровська область", lat: 48.5343, lng: 35.8709 },
  { name: "Нікополь", slug: "nikopol", oblast: "Дніпропетровська область", lat: 47.5667, lng: 34.4 },
  { name: "Біла Церква", slug: "bila-tserkva", oblast: "Київська область", lat: 49.7968, lng: 30.1311 },
  { name: "Бориспіль", slug: "boryspil", oblast: "Київська область", lat: 50.345, lng: 30.955 },
  { name: "Бровари", slug: "brovary", oblast: "Київська область", lat: 50.511, lng: 30.79 },
  { name: "Буча", slug: "bucha", oblast: "Київська область", lat: 50.543, lng: 30.221 },
  { name: "Ірпінь", slug: "irpin", oblast: "Київська область", lat: 50.5218, lng: 30.2506 },
  { name: "Гостомель", slug: "hostomel", oblast: "Київська область", lat: 50.5683, lng: 30.2651, aliases: ["гостомеля"] },
  { name: "Охтирка", slug: "okhtyrka", oblast: "Сумська область", lat: 50.3104, lng: 34.8988 },
  { name: "Донецьк", slug: "donetsk", oblast: "Донецька область", lat: 48.0159, lng: 37.8028 },
  { name: "Луганськ", slug: "luhansk", oblast: "Луганська область", lat: 48.574, lng: 39.3078, aliases: ["луганськ"] },
  { name: "Краматорськ", slug: "kramatorsk", oblast: "Донецька область", lat: 48.7389, lng: 37.5844 },
  { name: "Слов'янськ", slug: "sloviansk", oblast: "Донецька область", lat: 48.8667, lng: 37.6167 },
  { name: "Покровськ", slug: "pokrovsk", oblast: "Донецька область", lat: 48.2829, lng: 37.1819 },
  { name: "Авдіївка", slug: "avdiivka", oblast: "Донецька область", lat: 48.1399, lng: 37.7421, aliases: ["авдіївку", "авдіївці"] },
  { name: "Бахмут", slug: "bakhmut", oblast: "Донецька область", lat: 48.5948, lng: 37.9994, aliases: ["артемівськ", "артемовск"] },
  { name: "Костянтинівка", slug: "kostiantynivka", oblast: "Донецька область", lat: 48.5289, lng: 37.7069, aliases: ["костянтинівку"] },
  { name: "Дружківка", slug: "druzhkivka", oblast: "Донецька область", lat: 48.6212, lng: 37.5276 },
  { name: "Торецьк", slug: "toretsk", oblast: "Донецька область", lat: 48.3977, lng: 37.847 },
  { name: "Часів Яр", slug: "chasiv-yar", oblast: "Донецька область", lat: 48.5867, lng: 37.8361 },
  { name: "Сіверськ", slug: "siversk", oblast: "Донецька область", lat: 48.8667, lng: 38.1 },
  { name: "Маріуполь", slug: "mariupol", oblast: "Донецька область", lat: 47.0971, lng: 37.5434, aliases: ["маріуполя"] },
  { name: "Куп'янськ", slug: "kupiansk", oblast: "Харківська область", lat: 49.7087, lng: 37.6182, aliases: ["купянськ"] },
  { name: "Ізюм", slug: "izium", oblast: "Харківська область", lat: 49.2087, lng: 37.2563 },
  { name: "Балаклія", slug: "balakliia", oblast: "Харківська область", lat: 49.4601, lng: 36.8599, aliases: ["балаклію"] },
  { name: "Вовчанськ", slug: "vovchansk", oblast: "Харківська область", lat: 50.2908, lng: 36.9411, aliases: ["вовчанська"] },
  { name: "Мелітополь", slug: "melitopol", oblast: "Запорізька область", lat: 46.8489, lng: 35.3653 },
  { name: "Бердянськ", slug: "berdiansk", oblast: "Запорізька область", lat: 46.7664, lng: 36.7987 },
  { name: "Енергодар", slug: "enerhodar", oblast: "Запорізька область", lat: 47.4987, lng: 34.6552 },
  { name: "Токмак", slug: "tokmak", oblast: "Запорізька область", lat: 47.2552, lng: 35.7124 },
  { name: "Генічеськ", slug: "henichesk", oblast: "Херсонська область", lat: 46.1695, lng: 34.8034 },
  { name: "Нова Каховка", slug: "nova-kakhovka", oblast: "Херсонська область", lat: 46.7545, lng: 33.3486 },
  { name: "Олешки", slug: "oleshky", oblast: "Херсонська область", lat: 46.6404, lng: 32.7186 },
  { name: "Сімферополь", slug: "simferopol", oblast: "АР Крим", lat: 44.9521, lng: 34.1024 },
  { name: "Севастополь", slug: "sevastopol", oblast: "місто Севастополь", lat: 44.6167, lng: 33.5254 },
];

const apostrophePattern = /[’'`ʼ]/g;
const dashPattern = /[-–—]/g;
const spacesPattern = /\s+/g;
const stemEndings = [
  "ями",
  "ові",
  "еві",
  "ами",
  "ях",
  "ах",
  "ою",
  "ею",
  "ом",
  "ем",
  "ий",
  "ій",
  "ої",
  "ого",
  "ому",
  "а",
  "я",
  "у",
  "ю",
  "і",
  "ї",
  "е",
  "о",
  "и",
] as const;

export function normalizeCitySearchValue(value: string) {
  return value
    .toLowerCase()
    .trim()
    .replace(apostrophePattern, "")
    .replace(dashPattern, " ")
    .replace(spacesPattern, " ");
}

function stemCitySearchValue(value: string) {
  const normalized = normalizeCitySearchValue(value);

  if (normalized.length <= 4) {
    return normalized;
  }

  for (const ending of stemEndings) {
    if (normalized.endsWith(ending) && normalized.length - ending.length >= 4) {
      return normalized.slice(0, -ending.length);
    }
  }

  return normalized;
}

function levenshteinDistance(left: string, right: string) {
  if (left === right) {
    return 0;
  }

  if (!left.length) {
    return right.length;
  }

  if (!right.length) {
    return left.length;
  }

  const previous = Array.from({ length: right.length + 1 }, (_, index) => index);
  const current = new Array(right.length + 1).fill(0);

  for (let i = 0; i < left.length; i += 1) {
    current[0] = i + 1;

    for (let j = 0; j < right.length; j += 1) {
      const cost = left[i] === right[j] ? 0 : 1;
      current[j + 1] = Math.min(
        current[j] + 1,
        previous[j + 1] + 1,
        previous[j] + cost,
      );
    }

    previous.splice(0, previous.length, ...current);
  }

  return previous[right.length];
}

export function scoreCitySearchMatch(
  query: string,
  target: {
    name: string;
    slug: string;
    oblast: string;
    aliases?: string[];
  },
) {
  const normalizedQuery = normalizeCitySearchValue(query);

  if (normalizedQuery.length < 2) {
    return 0;
  }

  const stemmedQuery = stemCitySearchValue(normalizedQuery);
  const tokens = [target.name, target.slug, target.oblast, ...(target.aliases ?? [])];
  let bestScore = 0;

  for (const token of tokens) {
    const normalizedToken = normalizeCitySearchValue(token);
    const stemmedToken = stemCitySearchValue(normalizedToken);

    if (normalizedToken === normalizedQuery || stemmedToken === stemmedQuery) {
      bestScore = Math.max(bestScore, 140);
      continue;
    }

    if (normalizedToken.startsWith(normalizedQuery) || stemmedToken.startsWith(stemmedQuery)) {
      bestScore = Math.max(bestScore, 120 - Math.max(0, normalizedToken.length - normalizedQuery.length));
      continue;
    }

    if (normalizedToken.includes(normalizedQuery) || stemmedToken.includes(stemmedQuery)) {
      bestScore = Math.max(bestScore, 92 - Math.max(0, normalizedToken.length - normalizedQuery.length));
      continue;
    }

    const maxDistance = normalizedQuery.length >= 8 ? 3 : normalizedQuery.length >= 5 ? 2 : 1;
    const distance = Math.min(
      levenshteinDistance(normalizedQuery, normalizedToken),
      levenshteinDistance(stemmedQuery, stemmedToken),
    );

    if (distance <= maxDistance) {
      bestScore = Math.max(bestScore, 72 - distance * 10);
    }
  }

  return bestScore;
}
