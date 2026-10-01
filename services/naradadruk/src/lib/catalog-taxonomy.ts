export const storefrontCategories = [
  { slug: "strajkbol", name: "Страйкбол", description: "Аксесуари та кріплення для страйкбольного спорядження.", sortOrder: 10 },
  { slug: "setup", name: "Для сетапу", description: "Підставки, тримачі й органайзери для робочого простору.", sortOrder: 20 },
  { slug: "dekor", name: "Дім і декор", description: "Практичні й декоративні вироби для дому.", sortOrder: 30 },
  { slug: "inshe", name: "Інше", description: "Інші практичні вироби під вашу задачу.", sortOrder: 40 },
];

export function suggestedCategory(title: string, currentSlug: string) {
  if (!["inshe", "dekor", "strajkbol", "setup"].includes(currentSlug)) return currentSlug;
  if (/глушник|m-lok|страйкбол|привод|шолом|glock|picatinny|molle|коліматор|магазин.*(?:ак|ar)/i.test(title)) return "strajkbol";
  if (/hyperx|відеокарт|навушник|кабел|sk[åa]dis|настільний органайзер/i.test(title)) return "setup";
  return currentSlug;
}

export function legacyCategorySlug(value: string) {
  const normalized = value.trim().toLocaleLowerCase("uk-UA");
  return ({ "декор": "dekor", "strikeball": "strajkbol", "страйкбол": "strajkbol", "для сетапу": "setup", "дім і декор": "dekor", "інше": "inshe" } as Record<string,string>)[normalized] ?? normalized;
}
