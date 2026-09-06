// Explicit administrative subscriptions. No coordinates or object positions are inferred.
export interface BulletinArea {
  id: string;
  label: string;
  aliases: string[];
  parent?: string;
}
export const AREAS: BulletinArea[] = [
  {
    id: "kyiv",
    label: "Київ",
    aliases: ["київ", "києві", "києва", "києву", "киев", "киеве", "кияни"],
  },
  {
    id: "kyiv-oblast",
    label: "Київська область",
    aliases: [
      "київська область",
      "київській області",
      "київської області",
      "київщині",
      "київщина",
      "київщини",
      "киевская область",
    ],
  },
  ...[
    ["bucha-raion", "Бучанський район", "бучанськ"],
    ["brovary-raion", "Броварський район", "броварськ"],
    ["boryspil-raion", "Бориспільський район", "бориспільськ"],
    ["bilatserkva-raion", "Білоцерківський район", "білоцерківськ"],
    ["vyshhorod-raion", "Вишгородський район", "вишгородськ"],
    ["obukhiv-raion", "Обухівський район", "обухівськ"],
    ["fastiv-raion", "Фастівський район", "фастівськ"],
  ].map(([id, label, stem]) => ({
    id,
    label,
    parent: "kyiv-oblast",
    aliases: ["ий", "ому", "ого", "ім"].map((suffix) => `${stem}${suffix}`),
  })),
  ...[
    [
      "brovary",
      "Бровари",
      "brovary-raion",
      "бровари|броварах|броварів|броварам",
    ],
    [
      "boryspil",
      "Бориспіль",
      "boryspil-raion",
      "бориспіль|борисполі|борисполя|борисполю",
    ],
    ["bucha", "Буча", "bucha-raion", "буча|бучі|бучу|бучі"],
    ["irpin", "Ірпінь", "bucha-raion", "ірпінь|ірпені|ірпеня|ірпеню"],
    [
      "vyshhorod",
      "Вишгород",
      "vyshhorod-raion",
      "вишгород|вишгороді|вишгорода|вишгороду",
    ],
    ["obukhiv", "Обухів", "obukhiv-raion", "обухів|обухові|обухова|обухову"],
    [
      "vasylkiv",
      "Васильків",
      "obukhiv-raion",
      "васильків|василькові|василькова|василькову",
    ],
    ["fastiv", "Фастів", "fastiv-raion", "фастів|фастові|фастова|фастову"],
    [
      "bilatserkva",
      "Біла Церква",
      "bilatserkva-raion",
      "біла церква|білій церкві|білу церкву|білої церкви",
    ],
    ["vyshneve", "Вишневе", "bucha-raion", "вишневе|вишневому"],
    ["boyarka", "Боярка", "fastiv-raion", "боярка|боярці|боярку"],
    [
      "slavutych",
      "Славутич",
      "vyshhorod-raion",
      "славутич|славутичі|славутича",
    ],
  ].map(([id, label, parent, aliases]) => ({
    id,
    label,
    parent,
    aliases: aliases.split("|"),
  })),
];
export function inheritedAreas(selected: string[]): Set<string> {
  const result = new Set<string>();
  for (const id of selected) {
    let area = AREAS.find((a) => a.id === id);
    while (area && !result.has(area.id)) {
      result.add(area.id);
      area = AREAS.find((a) => a.id === area!.parent);
    }
  }
  return result;
}
export function matchingAreas(
  selected: string[],
  mentioned: string[],
): string[] {
  const subscriptions = inheritedAreas(selected);
  return mentioned.filter((id) => subscriptions.has(id));
}
