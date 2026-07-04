import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const apiUrl = process.env.DEEPSTATE_API_URL;
const apiToken = process.env.DEEPSTATE_API_TOKEN;
const localGeojsonPath = process.env.DEEPSTATE_GEOJSON_PATH;
const outPath = path.resolve("src/data/importedFrontline.json");

async function loadGeojson() {
  if (localGeojsonPath) {
    return JSON.parse(await readFile(localGeojsonPath, "utf8"));
  }
  if (!apiUrl) {
    throw new Error("Set DEEPSTATE_GEOJSON_PATH or DEEPSTATE_API_URL before importing.");
  }
  const response = await fetch(apiUrl, {
    headers: apiToken ? { Authorization: `Bearer ${apiToken}` } : undefined,
  });
  if (!response.ok) {
    throw new Error(`DeepState API request failed: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

function flattenCoordinates(coords, result = []) {
  if (!Array.isArray(coords)) return result;
  if (typeof coords[0] === "number" && typeof coords[1] === "number") {
    result.push({ lat: Number(coords[1].toFixed(5)), lng: Number(coords[0].toFixed(5)) });
    return result;
  }
  for (const item of coords) flattenCoordinates(item, result);
  return result;
}

function simplifyEvery(points, step = 8) {
  if (points.length <= step * 2) return points;
  return points.filter((_, index) => index % step === 0 || index === points.length - 1);
}

function extractFeature(feature) {
  const geometry = feature?.geometry;
  if (!geometry?.coordinates) return null;
  const points = simplifyEvery(flattenCoordinates(geometry.coordinates));
  if (points.length < 2) return null;
  return {
    type: geometry.type,
    name: feature?.properties?.name || feature?.properties?.title || "Imported DeepState layer",
    points,
  };
}

const geojson = await loadGeojson();
if (geojson?.type !== "FeatureCollection" || !Array.isArray(geojson.features)) {
  throw new Error("Expected a GeoJSON FeatureCollection. Check the official API adapter/schema.");
}

const features = geojson.features.map(extractFeature).filter(Boolean);
await mkdir(path.dirname(outPath), { recursive: true });
await writeFile(outPath, `${JSON.stringify({ importedAt: new Date().toISOString(), features }, null, 2)}\n`);
console.log(`Imported ${features.length} static frontline/control features into ${outPath}`);
