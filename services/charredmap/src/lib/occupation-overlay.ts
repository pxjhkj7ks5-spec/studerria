import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { FeatureCollection } from "geojson";
import { normalizeOccupationOverlay } from "@/lib/occupation-overlay-shared";
export {
  normalizeOccupationOverlay,
  type OccupationOverlayFeature,
  type OccupationOverlayProperties,
} from "@/lib/occupation-overlay-shared";

function getOverlayFilePath() {
  return path.join(process.cwd(), "src/data/occupied-territories-editorial.geojson");
}

export async function getOccupationOverlay(): Promise<FeatureCollection> {
  try {
    const contents = await readFile(getOverlayFilePath(), "utf8");
    return normalizeOccupationOverlay(JSON.parse(contents) as FeatureCollection);
  } catch {
    return normalizeOccupationOverlay(null);
  }
}

export async function saveOccupationOverlay(overlay: FeatureCollection) {
  const normalized = normalizeOccupationOverlay(overlay);
  const filePath = getOverlayFilePath();

  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(normalized, null, 2)}\n`, "utf8");

  return normalized;
}
