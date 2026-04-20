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
  const explicitPath = process.env.OCCUPATION_OVERLAY_FILE?.trim();
  if (explicitPath) {
    return path.resolve(explicitPath);
  }

  const uploadDir = process.env.UPLOAD_DIR?.trim();
  if (uploadDir && path.isAbsolute(uploadDir)) {
    return path.join(path.dirname(uploadDir), "occupied-territories-editorial.geojson");
  }

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
