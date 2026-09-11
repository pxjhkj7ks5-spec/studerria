import { describe, it, expect } from "vitest";
import { nearbySettlements, zoneAreas } from "../src/bulletins/settlements.js";
import { parseBulletin } from "../src/bulletins/parser.js";
import { haversineDistance } from "../src/engine/geometry.js";
const point = { lat: 50.32571, lon: 30.71474, radiusKm: 3 };
describe("civil radius subscriptions", () => {
  it("includes Hnidyn, excludes distant places, and uses the exact radius boundary", () => {
    const places = nearbySettlements(point, 3);
    expect(places.some((p) => p.label === "Гнідин")).toBe(true);
    expect(places.every((p) => haversineDistance(point, p) <= 3)).toBe(true);
    expect(places.some((p) => p.label === "Бровари")).toBe(false);
    expect(nearbySettlements(point, 20).length).toBeGreaterThan(places.length);
  });
  it.each([
    "Гнідин",
    "Гнідин: увага",
    "БпЛА у Гнідині",
    "До Гнідина, в укриття",
  ])("matches %s", (text) => {
    expect(parseBulletin(text, zoneAreas(point))).toMatchObject({
      kind: "warning",
      areaIds: expect.arrayContaining(["gn-708695"]),
    });
  });
  it("supports disabling radius", () =>
    expect(zoneAreas({ ...point, bulletinRadius: false })).toEqual([]));
  it.each(["Пуски балістики", "ОТРК", "Загроза балістичного озброєння"])(
    "flags immediate warning %s",
    (text) => {
      expect(parseBulletin(text)).toMatchObject({
        kind: "warning",
        urgent: true,
        areaIds: ["ballistic-general"],
      });
    },
  );
  it.each([
    "Вчора були пуски балістики",
    "Пусків балістики немає",
    "Тестова загроза ОТРК",
    "Балістика — не підтверджено",
    "Відбій загрози балістики",
    "Балістика! Відбій загрози балістики",
  ])("ignores non-current warning %s", (text) => {
    expect(parseBulletin(text).kind).not.toBe("warning");
  });
});
