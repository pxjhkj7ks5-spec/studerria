import { AREAS, type BulletinArea } from "./areas.js";
import type { Bulletin } from "./types.js";

export function normalizeText(input: string): string {
  const lookalikes: Record<string, string> = {
    a: "а",
    c: "с",
    e: "е",
    i: "і",
    o: "о",
    p: "р",
    x: "х",
    y: "у",
  };
  return input
    .normalize("NFKC")
    .toLocaleLowerCase("uk")
    .replace(/[\p{L}]+/gu, (word) =>
      /[а-яіїєґ]/u.test(word)
        ? word.replace(/[aceiopxy]/g, (c) => lookalikes[c])
        : word,
    )
    .replace(/[’ʼ`]/g, "'")
    .replace(/[^\p{L}\p{N}'\s]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
}
function editDistance(a: string, b: string): number {
  let row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 0; i < a.length; i++) {
    const next = [i + 1];
    for (let j = 0; j < b.length; j++)
      next[j + 1] = Math.min(
        next[j] + 1,
        row[j + 1] + 1,
        row[j] + Number(a[i] !== b[j]),
      );
    row = next;
  }
  return row[b.length];
}
function mentions(
  text: string,
  catalogue: BulletinArea[],
): { ids: string[]; fuzzy: boolean } {
  const words = text.split(" ");
  const ids = new Set<string>();
  let fuzzy = false;
  for (let i = 0; i < words.length; i++) {
    const exact = catalogue.filter((a) =>
      a.aliases.some(
        (alias) =>
          words.slice(i, i + alias.split(" ").length).join(" ") === alias,
      ),
    );
    if (exact.length) {
      exact.forEach((a) => ids.add(a.id));
      continue;
    }
    const word = words[i];
    if (word.length < 5) continue;
    const candidates = AREAS.filter((a) =>
      a.aliases.some(
        (alias) =>
          !alias.includes(" ") &&
          editDistance(word, alias) <= (word.length >= 9 ? 2 : 1),
      ),
    );
    if (candidates.length) {
      candidates.forEach((a) => ids.add(a.id));
      fuzzy = true;
    }
  }
  return { ids: [...ids].sort(), fuzzy };
}

/** Civil bulletins only: explicit warning language + explicit locality in the same sentence.
 * No object type/count, heading, position, reply inheritance or cross-post tracking.
 */
export function parseBulletin(
  input: string,
  catalogue: BulletinArea[] = AREAS,
): Bulletin {
  const result: Bulletin = {
    version: "civil-1",
    kind: "other",
    areaIds: [],
    uncertain: false,
    reasons: [],
  };
  const urgentAreas = new Set<string>();
  const states = new Map<string, "warning" | "all_clear_report">();
  const allClear =
    /(?:відбій|отбой|скасовано тривогу|тривог[ауи] (?:скасовано|немає))/u;
  const warning =
    /(?:повітрян[аоу] тривог|тривога|в укриття|до укритт|уважно|увага|небезпека|загроза)/u;
  const excluded =
    /(?:відбійник|навчан|навчальн|тестов|перевірка систем|вчора|позавчора|історі|реклама|підписуй|збір коштів|донат|дтп|авто |футбол|фільм|завтра|після відбою)/u;
  const negative =
    /(?:немає загроз|загроз[аи] немає|не підтверд|хибн|помилков|без загроз|не оголош|не було тривог|немає (?:балістик[а-яіїє]*|пуск)|пусків(?: балістик[а-яіїє]*| ракет)? немає|без (?:пуск|балістик)|не зафіксован|не підтверджен)/u;
  // Splitting clauses prevents attaching the place in an unrelated news paragraph to a warning.
  for (const clause of input.slice(0, 16384).split(/[\n.!?;]+/u)) {
    const normalized = normalizeText(clause);
    let corrected = false;
    const text = normalized
      .split(" ")
      .map((word) => {
        const vocabulary = [
          "тривога",
          "загроза",
          "увага",
          "уважно",
          "укриття",
          "відбій",
        ];
        if (word.length < 5 || vocabulary.includes(word)) return word;
        const matches = vocabulary.filter(
          (term) => editDistance(word, term) === 1,
        );
        if (matches.length !== 1) return word;
        corrected = true;
        return matches[0];
      })
      .join(" ");
    if (!text || excluded.test(text)) continue;
    const places = mentions(text, catalogue);
    const ballistic = /(?:балістик|баллистик|балістич|баллистич|отрк)/u.test(
      text,
    );
    if (ballistic && !places.ids.length) places.ids.push("ballistic-general");
    if (!places.ids.length) continue;
    if (allClear.test(text) || negative.test(text)) {
      places.ids.forEach((id) => {
        states.set(id, "all_clear_report");
        urgentAreas.delete(id);
      });
    } else if (
      places.ids.some((id) => id.startsWith("gn-")) ||
      warning.test(text) ||
      ballistic ||
      /(?:шахед|бпла|дрон|ракет)/u.test(text)
    ) {
      places.ids.forEach((id) => {
        states.set(id, "warning");
        if (ballistic) urgentAreas.add(id);
      });
    } else continue;
    result.uncertain ||=
      corrected ||
      places.fuzzy ||
      /(?:можлив|ймовір|імовір|попереднь|непідтвердж)/u.test(text);
    if (corrected)
      result.reasons.push(
        "Формулювання зіставлено з урахуванням можливої опечатки.",
      );
    if (places.fuzzy)
      result.reasons.push("Місце зіставлено з урахуванням можливої опечатки.");
  }
  result.kind = [...states.values()].includes("warning")
    ? "warning"
    : states.size
      ? "all_clear_report"
      : "other";
  result.areaIds = [...states]
    .filter(([, kind]) => kind === result.kind)
    .map(([id]) => id)
    .sort();
  if (
    result.kind === "warning" &&
    result.areaIds.some((id) => urgentAreas.has(id))
  )
    result.urgent = true;
  result.reasons = [...new Set(result.reasons)];
  if (result.areaIds.length)
    result.reasons.unshift(
      "Місце прямо назване джерелом; зіставлення з радіусом або додатковою підпискою.",
    );
  return result;
}
