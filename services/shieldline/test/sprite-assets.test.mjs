import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import sharp from "sharp";
import { launchSectors } from "../src/game/launchSystem.mjs";
import { launcherVariantForSector } from "../src/game/launcherVariants.ts";

const spriteRoot = new URL("../src/assets/sprites/", import.meta.url);
const modelFolders = ["units", "threats", "launch", "carriers"];

test("runtime model sprites are clean 96px RGBA assets", async () => {
  for (const folder of modelFolders) {
    const directory = new URL(`${folder}/`, spriteRoot);
    const files = (await readdir(directory)).filter((file) => file.endsWith(".png"));
    for (const file of files) {
      const source = new URL(file, directory);
      const image = sharp(fileURLToPath(source)).ensureAlpha();
      const { data, info } = await image.raw().toBuffer({ resolveWithObject: true });
      assert.equal(info.width, 96, `${folder}/${file} width`);
      assert.equal(info.height, 96, `${folder}/${file} height`);
      for (const [x, y] of [[0, 0], [95, 0], [0, 95], [95, 95]]) {
        assert.equal(data[(y * info.width + x) * info.channels + 3], 0, `${folder}/${file} corner alpha`);
      }
      for (let index = 0; index < data.length; index += info.channels) {
        const [red, green, blue, alpha] = data.subarray(index, index + 4);
        const magentaFringe = alpha > 0 && green < 105 && red > 125 && blue > 95 && red > green * 1.3 && blue > green * 1.22;
        assert.equal(magentaFringe, false, `${folder}/${file} contains magenta fringe`);
      }
    }
  }
});

test("launcher variants follow the active threat and sector", () => {
  const sea = launchSectors.find((sector) => sector.id === "sea_corridor_a");
  const air = launchSectors.find((sector) => sector.id === "long_range_air_c");
  const near = launchSectors.find((sector) => sector.id === "east_tactical_a");
  const deep = launchSectors.find((sector) => sector.id === "east_deep_b");
  assert.equal(launcherVariantForSector({ ...sea, activeThreatKind: "kalibr" }), "cruise-naval");
  assert.equal(launcherVariantForSector({ ...air, activeThreatKind: "kh101" }), "cruise-air");
  assert.equal(launcherVariantForSector({ ...near, activeThreatKind: "iskander" }), "ballistic-tactical-tel");
  assert.equal(launcherVariantForSector({ ...deep, activeThreatKind: "iskander" }), "ballistic-heavy-tel");
  assert.match(launcherVariantForSector({ ...near, activeThreatKind: "geran2" }), /^drone-(mobile|field)$/);
});
