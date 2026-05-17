import type { Feature, FeatureCollection, Geometry } from "geojson";
import { realBoundaries } from "@/lib/real-boundaries";

export type PeriodId = "1920s" | "1950s" | "1990s" | "2026";
export type AreaTone = "core" | "separate" | "colonial" | "claim";
export type MarkerKind = "treaty" | "status" | "conflict";

export type AtlasArea = {
  id: string;
  name: string;
  tone: AreaTone;
  summary: string;
  coordinates?: [number, number][][];
  geometry?: Geometry;
};

export type AtlasMarker = {
  id: string;
  kind: MarkerKind;
  title: string;
  kicker: string;
  summary: string;
  coordinates: [number, number];
};

export type AtlasPeriod = {
  id: PeriodId;
  label: string;
  range: string;
  title: string;
  summary: string;
  note: string;
  bounds: [[number, number], [number, number]];
  controlled: AtlasArea[];
  claims: AtlasArea[];
  markers: AtlasMarker[];
  keyEvents: string[];
  legalActs: string[];
};

export type AtlasSource = {
  title: string;
  url: string;
  note: string;
};

const mainlandChina: AtlasArea = {
  id: "mainland-china",
  name: "Материковий Китай",
  tone: "core",
  summary: "Сучасна державна геометрія КНР з відкритого набору geo-countries.",
  geometry: realBoundaries.china,
};

const republicClaim: AtlasArea = {
  ...mainlandChina,
  id: "republic-china-claim",
  name: "Заявлена територія Республіки Китай",
  summary: "Республіка Китай претендувала на широку спадкову територію, але фактичний контроль у 1920-х був фрагментований.",
};

const mongolia: AtlasArea = {
  id: "outer-mongolia",
  name: "Зовнішня Монголія / Монгольська Народна Республіка",
  tone: "separate",
  summary: "Після революції 1921 року фактично вийшла з-під китайського контролю; у 1924 році проголошено МНР.",
  geometry: realBoundaries.mongolia,
};

const tibet: AtlasArea = {
  id: "tibet",
  name: "Тибет",
  tone: "separate",
  summary: "У 1920-х подано як фактично автономний і спірний простір; після 1951 року інтегрований у контроль КНР.",
  geometry: realBoundaries.tibet,
};

const xinjiang: AtlasArea = {
  id: "xinjiang",
  name: "Сіньцзян",
  tone: "claim",
  summary: "У 1920-х номінально належав до китайської державної рамки, але мав високу автономність місцевих правителів.",
  geometry: realBoundaries.xinjiang,
};

const taiwan: AtlasArea = {
  id: "taiwan",
  name: "Тайвань",
  tone: "separate",
  summary: "З 1949 року керується окремо Республікою Китай; КНР вважає Тайвань частиною Китаю.",
  geometry: realBoundaries.taiwan,
};

const hongKong: AtlasArea = {
  id: "hong-kong",
  name: "Гонконг",
  tone: "colonial",
  summary: "Був під британською адміністрацією до передачі КНР 1 липня 1997 року.",
  geometry: realBoundaries.hongKong,
};

const macao: AtlasArea = {
  id: "macao",
  name: "Макао",
  tone: "colonial",
  summary: "Був під португальською адміністрацією до передачі КНР 20 грудня 1999 року.",
  geometry: realBoundaries.macau,
};

const aksaiChin: AtlasArea = {
  id: "aksai-chin",
  name: "Аксай-Чин",
  tone: "claim",
  summary: "Китай адмініструє Аксай-Чин; Індія вважає його частиною союзної території Ладакх.",
  coordinates: [[
    [78.0, 35.5],
    [79.7, 34.5],
    [80.9, 33.2],
    [79.8, 32.2],
    [77.4, 32.4],
    [76.7, 34.3],
    [78.0, 35.5],
  ]],
};

const arunachal: AtlasArea = {
  id: "arunachal-south-tibet",
  name: "Аруначал-Прадеш / претензія як Південний Тибет",
  tone: "claim",
  summary: "Індія адмініструє Аруначал-Прадеш; Китай претендує на значну частину як на Південний Тибет.",
  coordinates: [[
    [91.5, 29.2],
    [94.4, 29.3],
    [97.3, 28.4],
    [96.0, 27.2],
    [92.2, 27.2],
    [91.5, 29.2],
  ]],
};

const bhutanBorder: AtlasArea = {
  id: "bhutan-border",
  name: "Спірні ділянки кордону Бутану й Китаю",
  tone: "claim",
  summary: "Кілька західних і північних ділянок кордону Бутану й Китаю залишаються предметом переговорів.",
  coordinates: [[
    [88.6, 28.5],
    [90.2, 28.7],
    [91.2, 27.9],
    [90.1, 27.0],
    [88.7, 27.5],
    [88.6, 28.5],
  ]],
};

const senkaku: AtlasArea = {
  id: "senkaku-diaoyu",
  name: "Сенкаку / Дяоюйдао",
  tone: "claim",
  summary: "Острови адмініструє Японія; на них претендують Китай і Тайвань.",
  coordinates: [[
    [123.9, 26.2],
    [124.4, 26.2],
    [124.4, 25.8],
    [123.9, 25.8],
    [123.9, 26.2],
  ]],
};

const southChinaSea: AtlasArea = {
  id: "south-china-sea-claims",
  name: "Морські претензії у Південнокитайському морі",
  tone: "claim",
  summary: "Перехресні претензії охоплюють район Парасельських і Спратлійських островів та спірну «лінію дев'яти рисок».",
  coordinates: [[
    [109.0, 20.0],
    [114.0, 18.2],
    [118.0, 15.0],
    [120.0, 10.5],
    [118.8, 6.2],
    [114.2, 4.2],
    [110.4, 6.1],
    [108.7, 10.4],
    [108.2, 15.1],
    [109.0, 20.0],
  ]],
};

function resolveAreaGeometry(area: AtlasArea): Geometry {
  if (area.geometry) {
    return area.geometry;
  }
  return {
    type: "Polygon",
    coordinates: area.coordinates || [],
  };
}

function polygonFeature(area: AtlasArea): Feature<Geometry, { id: string; name: string; tone: AreaTone; summary: string }> {
  return {
    type: "Feature",
    properties: {
      id: area.id,
      name: area.name,
      tone: area.tone,
      summary: area.summary,
    },
    geometry: resolveAreaGeometry(area),
  };
}

export function toFeatureCollection(areas: AtlasArea[]): FeatureCollection<Geometry> {
  return {
    type: "FeatureCollection",
    features: areas.map(polygonFeature),
  };
}

export const atlasPeriods: AtlasPeriod[] = [
  {
    id: "1920s",
    label: "1920-ті",
    range: "1921-1929",
    title: "Китай як заявлена держава, але з фрагментованим контролем.",
    summary:
      "Республіка Китай претендувала на широку територію колишньої імперської рамки, однак Зовнішня Монголія, Тибет і частина прикордонних регіонів жили в режимі фактичної автономії або окремого контролю.",
    note: "Базовий шар показує заявлену державну рамку, а прозорі шари відділяють слабкий, фактично окремий або спірний контроль.",
    bounds: [[72, 16], [126, 53]],
    controlled: [republicClaim],
    claims: [mongolia, tibet, xinjiang],
    markers: [
      {
        id: "mongolia-1924",
        kind: "status",
        title: "Монгольська Народна Республіка",
        kicker: "1924",
        summary: "Після революції 1921 року Зовнішня Монголія стала фактично окремою політичною одиницею.",
        coordinates: [103.8, 47.9],
      },
      {
        id: "roc-nanjing",
        kind: "status",
        title: "Республіка Китай",
        kicker: "1920-ті",
        summary: "Республіка Китай лишалася міжнародною рамкою Китаю, хоча внутрішній контроль був нерівномірним.",
        coordinates: [116.4, 32.2],
      },
    ],
    keyEvents: [
      "1921: Монгольська революція спричинила фактичне відокремлення Зовнішньої Монголії від китайської політичної системи.",
      "1924: проголошення Монгольської Народної Республіки.",
      "1920-ті: Тибет і Сіньцзян залишались прикордонними просторами з особливим режимом контролю.",
    ],
    legalActs: [
      "Конституція і державні акти Монгольської Народної Республіки 1924 року закріпили новий статус Зовнішньої Монголії.",
      "Республіка Китай дипломатично визнала незалежність Монголії вже після плебісциту 1945 року, у січні 1946 року; це винесено як наслідок зміни статусу, а не подія 1920-х.",
    ],
  },
  {
    id: "1950s",
    label: "1950-ті",
    range: "1949-1959",
    title: "КНР контролює материковий Китай, Тайвань лишається окремо керованим.",
    summary:
      "Після 1949 року Китайська Народна Республіка стала фактичною владою на материку. Тибет був включений у контроль КНР після Угоди з 17 пунктів 1951 року, а Республіка Китай продовжила існувати на Тайвані.",
    note: "Гонконг і Макао у цьому зрізі показані як колоніально адміністровані анклави біля дельти Перлинної річки.",
    bounds: [[72, 12], [128, 53]],
    controlled: [mainlandChina, tibet],
    claims: [taiwan, hongKong, macao],
    markers: [
      {
        id: "prc-1949",
        kind: "status",
        title: "Китайська Народна Республіка",
        kicker: "1949",
        summary: "КНР стала фактичною владою на материковому Китаї після громадянської війни.",
        coordinates: [116.4, 39.9],
      },
      {
        id: "tibet-1951",
        kind: "treaty",
        title: "Угода з 17 пунктів",
        kicker: "23 травня 1951",
        summary: "Угода між Центральним народним урядом КНР і місцевим урядом Тибету щодо входження НВАК та регіональної автономії.",
        coordinates: [91.1, 29.7],
      },
      {
        id: "taiwan-roc",
        kind: "status",
        title: "Республіка Китай на Тайвані",
        kicker: "з 1949",
        summary: "Уряд Республіки Китай продовжив управління з Тайваню, що створило довготривалу проблему представництва Китаю.",
        coordinates: [121.0, 23.8],
      },
    ],
    keyEvents: [
      "1949: перемога Комуністичної партії Китаю на материку і створення Китайської Народної Республіки.",
      "1949: уряд Республіки Китай відступив на Тайвань.",
      "1951: Угода з 17 пунктів стала ключовою правовою рамкою контролю КНР над Тибетом у китайському державному трактуванні.",
    ],
    legalActs: [
      "Угода Центрального народного уряду і місцевого уряду Тибету про заходи для мирного визволення Тибету, підписана в Пекіні 23 травня 1951 року.",
      "Суб'єкти підписання: Центральний народний уряд КНР і делегація місцевого уряду Тибету; джерело China.org.cn подано як китайське державне трактування.",
    ],
  },
  {
    id: "1990s",
    label: "1990-ті",
    range: "1990-1999",
    title: "Повернення Гонконгу і Макао та нормалізація частини кордонів.",
    summary:
      "У 1990-х Китай отримав Гонконг і Макао як спеціальні адміністративні райони, а китайсько-радянська угода 1991 року зафіксувала важливий етап врегулювання східної ділянки кордону.",
    note: "Цей зріз підкреслює не розпад, а повернення колоніальних анклавів і договірну демаркацію.",
    bounds: [[72, 10], [130, 54]],
    controlled: [mainlandChina, hongKong, macao],
    claims: [taiwan, aksaiChin, arunachal],
    markers: [
      {
        id: "sino-soviet-1991",
        kind: "treaty",
        title: "Китайсько-радянська прикордонна угода",
        kicker: "16 травня 1991",
        summary: "Угоду щодо східної ділянки кордону підписали Цянь Цічень і Олександр Безсмертних.",
        coordinates: [133.0, 48.4],
      },
      {
        id: "hong-kong-1997",
        kind: "treaty",
        title: "Передача Гонконгу",
        kicker: "1 липня 1997",
        summary: "Китайсько-британська спільна декларація 1984 року і Основний закон Гонконгу 1990 року підготували передачу.",
        coordinates: [114.16, 22.32],
      },
      {
        id: "macao-1999",
        kind: "treaty",
        title: "Передача Макао",
        kicker: "20 грудня 1999",
        summary: "Китайсько-португальська спільна декларація 1987 року і Основний закон Макао 1993 року підготували передачу.",
        coordinates: [113.55, 22.17],
      },
    ],
    keyEvents: [
      "1991: угода щодо східної ділянки китайсько-радянського кордону.",
      "1997: Гонконг перейшов від британського управління до суверенітету КНР як спеціальний адміністративний район.",
      "1999: Макао перейшов від португальського управління до суверенітету КНР як спеціальний адміністративний район.",
    ],
    legalActs: [
      "Китайсько-британська спільна декларація, підписана в Пекіні 19 грудня 1984 року Маргарет Тетчер і Чжао Цзияном; передача Гонконгу відбулася 1 липня 1997 року.",
      "Основний закон Гонконгу ухвалений Всекитайськими зборами народних представників 4 квітня 1990 року, набрав чинності 1 липня 1997 року.",
      "Китайсько-португальська спільна декларація підписана 13 квітня 1987 року; Основний закон Макао ухвалений 31 березня 1993 року, набрав чинності 20 грудня 1999 року.",
      "Угода про східну ділянку кордону між СРСР і КНР, 16 травня 1991 року; повноважні представники: Цянь Цічень і Олександр Безсмертних.",
    ],
  },
  {
    id: "2026",
    label: "2026",
    range: "поточний стан",
    title: "Фактичний контроль плюс відкриті територіальні спори.",
    summary:
      "У 2026 році КНР контролює материковий Китай, Гонконг і Макао; Тайвань керується окремо, а низка сухопутних і морських спорів лишається предметом дипломатичної напруги.",
    note: "Спірні шари навмисно пунктирні й прозорі: це претензії або перехресні заяви сторін, а не підтверджені державні кордони.",
    bounds: [[72, 3], [134, 54]],
    controlled: [mainlandChina, hongKong, macao],
    claims: [taiwan, southChinaSea, aksaiChin, arunachal, senkaku, bhutanBorder],
    markers: [
      {
        id: "un-2758",
        kind: "treaty",
        title: "Резолюція ГА ООН 2758",
        kicker: "25 жовтня 1971",
        summary: "Представництво Китаю в ООН перейшло до КНР; політичний статус Тайваню залишається спірним.",
        coordinates: [121.0, 23.8],
      },
      {
        id: "south-china-sea",
        kind: "conflict",
        title: "Спори у Південнокитайському морі",
        kicker: "тривають",
        summary: "Перехресні морські й острівні претензії стосуються Китаю, Тайваню, В'єтнаму, Філіппін, Малайзії, Брунею та інших суб'єктів.",
        coordinates: [114.8, 10.2],
      },
      {
        id: "senkaku-claim",
        kind: "conflict",
        title: "Сенкаку / Дяоюйдао",
        kicker: "триває",
        summary: "Острови адмініструє Японія; на них претендують Китай і Тайвань.",
        coordinates: [124.15, 26.0],
      },
    ],
    keyEvents: [
      "Тайвань залишається окремо керованим, але КНР вважає його частиною Китаю.",
      "Претензії у Південнокитайському морі залишаються перехресними й частково мілітаризованими.",
      "Аксай-Чин, Аруначал-Прадеш / Південний Тибет, Сенкаку / Дяоюйдао і ділянки кордону з Бутаном залишаються активними або неврегульованими спірними шарами.",
    ],
    legalActs: [
      "Резолюція Генеральної Асамблеї ООН 2758, ухвалена 25 жовтня 1971 року, відновила представництво КНР в ООН.",
      "Основні закони Гонконгу і Макао залишаються конституційними рамками для спеціальних адміністративних районів.",
      "Для кількох показаних спірних шарів 2026 року немає фінального врегулювання; вони позначені як спірні або заявлені території, а не як усталені кордони.",
    ],
  },
];

export const atlasSources: AtlasSource[] = [
  {
    title: "OpenStreetMap",
    url: "https://www.openstreetmap.org/copyright",
    note: "Підкладка з актуальним картографічним контекстом.",
  },
  {
    title: "geoBoundaries",
    url: "https://www.geoboundaries.org/",
    note: "Відкрита геометрія адміністративних меж КНР на рівні ADM1, зокрема Тибету, Сіньцзяну, Гонконгу і Макао.",
  },
  {
    title: "geo-countries",
    url: "https://github.com/datasets/geo-countries",
    note: "Відкрита геометрія державного рівня ADM0 для Китаю, Тайваню і Монголії.",
  },
  {
    title: "National Geographic: політика картографування",
    url: "https://www.nationalgeographic.org/society/national-geographic-map-policy/",
    note: "Використано для підходу «фактичний контроль плюс окреме маркування спірних меж».",
  },
  {
    title: "National Geographic MapMaker: навчальна мапа",
    url: "https://www.nationalgeographic.org/society/learn/mapmaker-launch-guide/",
    note: "Навчальний картографічний орієнтир із завдання.",
  },
  {
    title: "WorldAtlas: територіальні конфлікти і спори у Південнокитайському морі",
    url: "https://www.worldatlas.com/articles/south-china-sea-territorial-conflicts-and-disputes.html",
    note: "Огляд перехресних претензій у Південнокитайському морі.",
  },
  {
    title: "Britannica: Китай",
    url: "https://www.britannica.com/place/China",
    note: "Сучасний адміністративний і географічний контекст Китаю.",
  },
  {
    title: "Britannica: Тайвань",
    url: "https://www.britannica.com/place/Taiwan/Government-and-society",
    note: "Контекст окремого управління Тайванем після 1949 року і представництва Китаю до 1971 року.",
  },
  {
    title: "Britannica: історія Монголії",
    url: "https://www.britannica.com/place/Mongolia/Independence-and-revolution",
    note: "Події 1921 року і проголошення Монгольської Народної Республіки у 1924 році.",
  },
  {
    title: "Britannica: Тибет після 1900 року",
    url: "https://www.britannica.com/place/Tibet/Tibet-since-1900",
    note: "Контекст фактичної автономії Тибету до 1951 року і спірності джерел щодо угоди.",
  },
  {
    title: "Britannica: Гонконг",
    url: "https://www.britannica.com/place/Hong-Kong",
    note: "Історичний контекст передачі Гонконгу і склад території.",
  },
  {
    title: "Britannica: передача Гонконгу",
    url: "https://www.britannica.com/event/handover-of-Hong-Kong",
    note: "Передача Гонконгу КНР 1 липня 1997 року.",
  },
  {
    title: "Britannica: Макао",
    url: "https://www.britannica.com/place/Macau-administrative-region-China",
    note: "Передача Макао КНР 20 грудня 1999 року.",
  },
  {
    title: "Britannica: острови Сенкаку",
    url: "https://www.britannica.com/place/Senkaku-Islands",
    note: "Огляд спору щодо островів Сенкаку / Дяоюйдао.",
  },
  {
    title: "Britannica: Аксай-Чин",
    url: "https://www.britannica.com/place/Aksai-Chin",
    note: "Контекст китайського адміністрування Аксай-Чину і претензії Індії.",
  },
  {
    title: "Britannica: лінія Мак-Магона",
    url: "https://www.britannica.com/event/McMahon-Line",
    note: "Контекст спору на північно-східному кордоні Індії та Китаю біля Аруначал-Прадеш.",
  },
  {
    title: "UN Digital Library: резолюція 2758",
    url: "https://digitallibrary.un.org/record/654350?ln=en",
    note: "Представництво Китаю в ООН, резолюція ухвалена 25 жовтня 1971 року.",
  },
  {
    title: "China.org.cn: Угода з 17 пунктів",
    url: "https://www.china.org.cn/english/Tibet/13236.htm",
    note: "Китайське державне трактування Угоди з 17 пунктів 1951 року щодо Тибету.",
  },
  {
    title: "Основний закон Гонконгу",
    url: "https://www.basiclaw.gov.hk/en/basiclaw/basiclaw.html",
    note: "Ухвалений 4 квітня 1990 року, набрав чинності 1 липня 1997 року.",
  },
  {
    title: "UN Treaty Series: Китайсько-британська спільна декларація",
    url: "https://treaties.un.org/doc/Publication/UNTS/Volume%201399/v1399.pdf",
    note: "Підписана в Пекіні 19 грудня 1984 року.",
  },
  {
    title: "Основний закон Макао",
    url: "https://www.ecoi.net/en/document/1264859.html",
    note: "Ухвалений 31 березня 1993 року, набрав чинності 20 грудня 1999 року.",
  },
  {
    title: "UN Treaty Series: матеріали щодо Макао",
    url: "https://treaties.un.org/doc/Publication/UNTS/Volume%202100/v2100.pdf",
    note: "Матеріали щодо китайсько-португальської декларації 13 квітня 1987 року і передачі 1999 року.",
  },
  {
    title: "PA-X: китайсько-радянська прикордонна угода 1991 року",
    url: "https://www.peaceagreements.org/agreements/1740/",
    note: "Метадані угоди і відомості про підписантів.",
  },
];

export const initialPeriod = atlasPeriods[0];
