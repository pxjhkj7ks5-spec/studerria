import { readFile } from "node:fs/promises";
import path from "node:path";
import type { FeatureCollection } from "geojson";

const fallbackOverlay: FeatureCollection = {
  type: "FeatureCollection",
  features: [],
};

export async function getOccupationOverlay(): Promise<FeatureCollection> {
  try {
    const filePath = path.join(
      process.cwd(),
      "src/data/occupied-territories-editorial.geojson",
    );
    const contents = await readFile(filePath, "utf8");
    return JSON.parse(contents) as FeatureCollection;
  } catch {
    return fallbackOverlay;
  }
}
