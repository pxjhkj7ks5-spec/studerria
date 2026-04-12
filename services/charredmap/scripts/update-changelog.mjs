import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const rootDir = process.cwd();
const changelogPath = path.join(rootDir, "changelog.json");
const versionPath = path.join(rootDir, "version.json");

const versionInfo = JSON.parse(readFileSync(versionPath, "utf8"));

function loadGitLog() {
  const raw = execSync("git log --pretty=format:%H%x1f%s%x1f%cI", {
    cwd: rootDir,
    encoding: "utf8",
  });

  if (!raw.trim()) {
    return [];
  }

  return raw
    .split("\n")
    .map((line) => {
      const [hash, message, date] = line.split("\u001f");
      return {
        hash,
        shortHash: hash.slice(0, 7),
        message,
        date,
      };
    })
    .filter((entry) => !entry.message.startsWith("chore: update changelog"));
}

const changelog = {
  version: versionInfo.version,
  generatedAt: new Date().toISOString(),
  entries: loadGitLog(),
};

writeFileSync(changelogPath, `${JSON.stringify(changelog, null, 2)}\n`);
