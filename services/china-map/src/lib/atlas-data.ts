import type { Feature, FeatureCollection, Polygon } from "geojson";

export type PeriodId = "1920s" | "1950s" | "1990s" | "2026";
export type AreaTone = "core" | "separate" | "colonial" | "claim";
export type MarkerKind = "treaty" | "status" | "conflict";

export type AtlasArea = {
  id: string;
  name: string;
  tone: AreaTone;
  summary: string;
  coordinates: [number, number][][];
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
  name: "Mainland China",
  tone: "core",
  summary: "Approximate classroom outline for the Chinese state core.",
  coordinates: [[
    [73.6, 39.5],
    [76.4, 35.2],
    [79.8, 31.2],
    [83.1, 29.0],
    [88.0, 27.8],
    [93.2, 27.6],
    [97.5, 24.6],
    [101.4, 21.6],
    [106.3, 20.7],
    [110.4, 21.5],
    [114.2, 22.3],
    [118.8, 24.7],
    [121.8, 28.4],
    [122.6, 33.1],
    [120.7, 37.0],
    [124.2, 40.1],
    [128.1, 43.5],
    [126.4, 47.8],
    [121.0, 50.3],
    [114.2, 49.1],
    [108.7, 47.8],
    [103.2, 48.6],
    [96.6, 44.7],
    [90.3, 45.6],
    [84.6, 45.0],
    [79.2, 42.4],
    [73.6, 39.5],
  ]],
};

const republicClaim: AtlasArea = {
  ...mainlandChina,
  id: "republic-china-claim",
  name: "Republic of China claimed territory",
  summary: "The Republic of China claimed a broad state territory, while actual control varied by region.",
};

const mongolia: AtlasArea = {
  id: "outer-mongolia",
  name: "Outer Mongolia / Mongolian People's Republic",
  tone: "separate",
  summary: "Factually outside Chinese control after the 1921 revolution and 1924 republic.",
  coordinates: [[
    [87.8, 49.0],
    [94.4, 46.1],
    [103.8, 46.6],
    [113.2, 44.4],
    [119.8, 47.1],
    [116.4, 50.6],
    [108.8, 52.1],
    [98.0, 51.8],
    [90.6, 50.7],
    [87.8, 49.0],
  ]],
};

const tibet: AtlasArea = {
  id: "tibet",
  name: "Tibet",
  tone: "separate",
  summary: "Presented as de facto autonomous/disputed in the 1920s; integrated into PRC control after 1951.",
  coordinates: [[
    [78.2, 34.7],
    [82.8, 31.0],
    [88.7, 28.0],
    [96.0, 27.4],
    [101.1, 29.4],
    [99.2, 33.7],
    [92.4, 35.4],
    [85.0, 36.0],
    [78.2, 34.7],
  ]],
};

const xinjiang: AtlasArea = {
  id: "xinjiang",
  name: "Xinjiang",
  tone: "claim",
  summary: "Nominally Chinese in the 1920s, with high autonomy under local governors and warlord politics.",
  coordinates: [[
    [73.6, 39.7],
    [79.2, 42.4],
    [84.6, 45.0],
    [90.3, 45.6],
    [96.6, 44.7],
    [94.1, 39.6],
    [88.0, 36.8],
    [80.6, 36.9],
    [73.6, 39.7],
  ]],
};

const taiwan: AtlasArea = {
  id: "taiwan",
  name: "Taiwan",
  tone: "separate",
  summary: "Governed separately by the Republic of China since 1949; claimed by the PRC.",
  coordinates: [[
    [120.0, 25.4],
    [121.8, 25.0],
    [122.2, 23.8],
    [121.5, 22.0],
    [120.5, 21.9],
    [119.7, 23.2],
    [120.0, 25.4],
  ]],
};

const hongKong: AtlasArea = {
  id: "hong-kong",
  name: "Hong Kong",
  tone: "colonial",
  summary: "British-administered until the 1 July 1997 handover.",
  coordinates: [[
    [113.82, 22.52],
    [114.35, 22.5],
    [114.42, 22.17],
    [113.86, 22.12],
    [113.82, 22.52],
  ]],
};

const macao: AtlasArea = {
  id: "macao",
  name: "Macao",
  tone: "colonial",
  summary: "Portuguese-administered until the 20 December 1999 handover.",
  coordinates: [[
    [113.48, 22.25],
    [113.62, 22.24],
    [113.64, 22.12],
    [113.5, 22.09],
    [113.48, 22.25],
  ]],
};

const aksaiChin: AtlasArea = {
  id: "aksai-chin",
  name: "Aksai Chin",
  tone: "claim",
  summary: "China administers Aksai Chin; India claims it as part of Ladakh.",
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
  name: "Arunachal Pradesh / South Tibet claim",
  tone: "claim",
  summary: "India administers Arunachal Pradesh; China claims large parts as South Tibet.",
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
  name: "Bhutan-China disputed border areas",
  tone: "claim",
  summary: "Several western and northern Bhutan border areas remain disputed in negotiations.",
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
  name: "Senkaku / Diaoyu Islands",
  tone: "claim",
  summary: "Administered by Japan; claimed by China and Taiwan.",
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
  name: "South China Sea maritime claims",
  tone: "claim",
  summary: "Overlapping claims include the Paracel and Spratly areas and the nine-dash-line dispute.",
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

function polygonFeature(area: AtlasArea): Feature<Polygon, { id: string; name: string; tone: AreaTone; summary: string }> {
  return {
    type: "Feature",
    properties: {
      id: area.id,
      name: area.name,
      tone: area.tone,
      summary: area.summary,
    },
    geometry: {
      type: "Polygon",
      coordinates: area.coordinates,
    },
  };
}

export function toFeatureCollection(areas: AtlasArea[]): FeatureCollection<Polygon> {
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
      "Республіка Китай претендувала на широку територію, однак Outer Mongolia, Tibet і частина прикордонних регіонів жили в режимі фактичної автономії або окремого контролю.",
    note: "На мапі базова територія показує заявлену державну рамку, а прозорі шари показують слабкий або спірний контроль.",
    bounds: [[72, 16], [126, 53]],
    controlled: [republicClaim],
    claims: [mongolia, tibet, xinjiang],
    markers: [
      {
        id: "mongolia-1924",
        kind: "status",
        title: "Mongolian People's Republic",
        kicker: "1924",
        summary: "Після революції 1921 року Outer Mongolia стала фактично окремою політичною одиницею.",
        coordinates: [103.8, 47.9],
      },
      {
        id: "roc-nanjing",
        kind: "status",
        title: "Republic of China",
        kicker: "1920s",
        summary: "ROC лишалася міжнародною рамкою Китаю, хоча внутрішній контроль був нерівномірним.",
        coordinates: [116.4, 32.2],
      },
    ],
    keyEvents: [
      "1921: Mongolian Revolution створила фактичне відокремлення Outer Mongolia від китайської політичної системи.",
      "1924: проголошення Mongolian People's Republic.",
      "1920-ті: Tibet і Xinjiang залишались прикордонними просторами з особливим режимом контролю.",
    ],
    legalActs: [
      "Конституційні та урядові акти Mongolian People's Republic 1924 року закріпили новий статус Outer Mongolia.",
      "Дипломатичне визнання Монголії Республікою Китай відбулося вже після плебісциту 1945 року, у січні 1946 року.",
    ],
  },
  {
    id: "1950s",
    label: "1950-ті",
    range: "1949-1959",
    title: "КНР контролює mainland, Taiwan лишається окремо керованим.",
    summary:
      "Після 1949 року People's Republic of China стала владою на mainland. Tibet був інтегрований через 17-Point Agreement 1951, а ROC продовжила існувати на Taiwan.",
    note: "Hong Kong і Macao все ще показані як колоніально адміністровані анклави біля Pearl River Delta.",
    bounds: [[72, 12], [128, 53]],
    controlled: [mainlandChina, tibet],
    claims: [taiwan, hongKong, macao],
    markers: [
      {
        id: "prc-1949",
        kind: "status",
        title: "People's Republic of China",
        kicker: "1949",
        summary: "КНР стала фактичною владою на mainland China після громадянської війни.",
        coordinates: [116.4, 39.9],
      },
      {
        id: "tibet-1951",
        kind: "treaty",
        title: "17-Point Agreement",
        kicker: "23 May 1951",
        summary: "Угода між Central People's Government і Local Government of Tibet щодо входження PLA і регіональної автономії.",
        coordinates: [91.1, 29.7],
      },
      {
        id: "taiwan-roc",
        kind: "status",
        title: "ROC on Taiwan",
        kicker: "since 1949",
        summary: "Уряд ROC продовжив управління з Taiwan, що створило довготривалу проблему представництва Китаю.",
        coordinates: [121.0, 23.8],
      },
    ],
    keyEvents: [
      "1949: перемога CCP на mainland і створення People's Republic of China.",
      "1949: уряд Republic of China відступив на Taiwan.",
      "1951: 17-Point Agreement став ключовою правовою рамкою китайського контролю над Tibet у трактуванні КНР.",
    ],
    legalActs: [
      "Agreement of the Central People's Government and the Local Government of Tibet on Measures for the Peaceful Liberation of Tibet, signed in Beijing, 23 May 1951.",
      "Підписанти/суб'єкти: Central People's Government of the PRC і делегація Local Government of Tibet.",
    ],
  },
  {
    id: "1990s",
    label: "1990-ті",
    range: "1990-1999",
    title: "Повернення Hong Kong і Macao та нормалізація частини кордонів.",
    summary:
      "У 1990-х Китай отримав Hong Kong і Macao як Special Administrative Regions, а 1991 Sino-Soviet Border Agreement зафіксував важливий етап врегулювання східної ділянки кордону.",
    note: "Цей зріз підкреслює не розпад, а повернення колоніальних анклавів і договірну демаркацію.",
    bounds: [[72, 10], [130, 54]],
    controlled: [mainlandChina, hongKong, macao],
    claims: [taiwan, aksaiChin, arunachal],
    markers: [
      {
        id: "sino-soviet-1991",
        kind: "treaty",
        title: "Sino-Soviet Border Agreement",
        kicker: "16 May 1991",
        summary: "Підписаний Qian Qichen і Alexander Bessmertnykh для східної ділянки кордону.",
        coordinates: [133.0, 48.4],
      },
      {
        id: "hong-kong-1997",
        kind: "treaty",
        title: "Hong Kong handover",
        kicker: "1 July 1997",
        summary: "Sino-British Joint Declaration 1984 і Hong Kong Basic Law 1990 підготували передачу.",
        coordinates: [114.16, 22.32],
      },
      {
        id: "macao-1999",
        kind: "treaty",
        title: "Macao handover",
        kicker: "20 Dec 1999",
        summary: "Sino-Portuguese Joint Declaration 1987 і Macao Basic Law 1993 підготували передачу.",
        coordinates: [113.55, 22.17],
      },
    ],
    keyEvents: [
      "1991: agreement on the eastern section of the Sino-Soviet boundary.",
      "1997: Hong Kong returned from British to Chinese sovereignty as HKSAR.",
      "1999: Macao returned from Portuguese to Chinese sovereignty as MSAR.",
    ],
    legalActs: [
      "Sino-British Joint Declaration, signed at Beijing on 19 December 1984 by Margaret Thatcher and Zhao Ziyang; handover on 1 July 1997.",
      "Hong Kong Basic Law adopted by the National People's Congress on 4 April 1990, effective 1 July 1997.",
      "Sino-Portuguese Joint Declaration signed on 13 April 1987; Macao Basic Law adopted 31 March 1993, effective 20 December 1999.",
      "Agreement on the Eastern Section of the Boundary between the USSR and PRC, 16 May 1991; plenipotentiaries Qian Qichen and Alexander Bessmertnykh.",
    ],
  },
  {
    id: "2026",
    label: "2026",
    range: "current",
    title: "Фактичний контроль плюс відкриті територіальні спори.",
    summary:
      "У 2026 році PRC контролює mainland, Hong Kong і Macao; Taiwan керується окремо, а низка сухопутних і морських спорів лишається предметом дипломатичної напруги.",
    note: "Спірні шари навмисно пунктирні й прозорі: це претензії або overlapping claims, не підтверджені кордони.",
    bounds: [[72, 3], [134, 54]],
    controlled: [mainlandChina, hongKong, macao],
    claims: [taiwan, southChinaSea, aksaiChin, arunachal, senkaku, bhutanBorder],
    markers: [
      {
        id: "un-2758",
        kind: "treaty",
        title: "UN Resolution 2758",
        kicker: "25 Oct 1971",
        summary: "UN seat representation shifted to the PRC; Taiwan's status remains politically contested.",
        coordinates: [121.0, 23.8],
      },
      {
        id: "south-china-sea",
        kind: "conflict",
        title: "South China Sea disputes",
        kicker: "ongoing",
        summary: "Overlapping maritime and island claims involve China, Taiwan, Vietnam, Philippines, Malaysia, Brunei and others.",
        coordinates: [114.8, 10.2],
      },
      {
        id: "senkaku-claim",
        kind: "conflict",
        title: "Senkaku / Diaoyu",
        kicker: "ongoing",
        summary: "Administered by Japan, claimed by China and Taiwan.",
        coordinates: [124.15, 26.0],
      },
    ],
    keyEvents: [
      "Taiwan remains separately governed while claimed by the PRC.",
      "South China Sea claims remain overlapping and militarized in parts.",
      "Aksai Chin, Arunachal/South Tibet, Senkaku/Diaoyu and Bhutan border areas remain active or unresolved dispute layers.",
    ],
    legalActs: [
      "UN General Assembly Resolution 2758, adopted 25 October 1971, restored PRC representation at the UN.",
      "Hong Kong Basic Law and Macao Basic Law remain constitutional frameworks for the SARs.",
      "No final settlement exists for several highlighted 2026 dispute layers; they are shown as approximate claims.",
    ],
  },
];

export const atlasSources: AtlasSource[] = [
  {
    title: "National Geographic Map Policy",
    url: "https://www.nationalgeographic.org/society/national-geographic-map-policy/",
    note: "Used for the de facto + disputed-boundary cartographic stance.",
  },
  {
    title: "National Geographic MapMaker",
    url: "https://www.nationalgeographic.org/society/learn/mapmaker-launch-guide/",
    note: "Classroom mapping reference from the task brief.",
  },
  {
    title: "WorldAtlas: South China Sea Territorial Conflicts And Disputes",
    url: "https://www.worldatlas.com/articles/south-china-sea-territorial-conflicts-and-disputes.html",
    note: "Overview of overlapping South China Sea claims.",
  },
  {
    title: "Britannica: China",
    url: "https://www.britannica.com/place/China",
    note: "Current administrative framing and geographic context.",
  },
  {
    title: "Britannica: Hong Kong",
    url: "https://www.britannica.com/place/Hong-Kong",
    note: "Historical handover context and territorial composition.",
  },
  {
    title: "Britannica: Senkaku Islands",
    url: "https://www.britannica.com/place/Senkaku-Islands",
    note: "Senkaku/Diaoyu dispute summary.",
  },
  {
    title: "UN Digital Library: Resolution 2758",
    url: "https://digitallibrary.un.org/record/654350?ln=en",
    note: "UN representation of China, adopted 25 October 1971.",
  },
  {
    title: "China.org.cn: 17-Article Agreement",
    url: "https://www.china.org.cn/english/Tibet/13236.htm",
    note: "Chinese state-source framing of the 1951 Tibet agreement.",
  },
  {
    title: "Hong Kong Basic Law",
    url: "https://www.basiclaw.gov.hk/en/basiclaw/basiclaw.html",
    note: "Adopted 4 April 1990, effective 1 July 1997.",
  },
  {
    title: "UN Treaty Series: Sino-British Joint Declaration",
    url: "https://treaties.un.org/doc/Publication/UNTS/Volume%201399/v1399.pdf",
    note: "Signed at Beijing on 19 December 1984.",
  },
  {
    title: "Macao Basic Law",
    url: "https://www.ecoi.net/en/document/1264859.html",
    note: "Adopted 31 March 1993, effective 20 December 1999.",
  },
  {
    title: "UN Treaty Series: Macao notifications",
    url: "https://treaties.un.org/doc/Publication/UNTS/Volume%202100/v2100.pdf",
    note: "References the 13 April 1987 Sino-Portuguese Joint Declaration and 1999 handover.",
  },
  {
    title: "PA-X: 1991 Sino-Soviet Border Agreement",
    url: "https://www.peaceagreements.org/agreements/1740/",
    note: "Agreement metadata and signatory information.",
  },
];

export const initialPeriod = atlasPeriods[0];
