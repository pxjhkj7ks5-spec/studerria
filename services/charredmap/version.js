#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");

const rootDir = __dirname;
const versionJsonPath = path.join(rootDir, "version.json");

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function parseVersion(version) {
  const [major, minor, patch] = version.split(".").map((part) => Number.parseInt(part, 10));

  if ([major, minor, patch].some((part) => Number.isNaN(part))) {
    throw new Error(`Invalid version: ${version}`);
  }

  return { major, minor, patch };
}

function formatDisplayVersion({ major, minor, patch }) {
  return `${major}.${minor}.${String(patch).padStart(2, "0")}`;
}

function bumpPatch(currentVersion) {
  const parsed = parseVersion(currentVersion);
  parsed.patch += 1;
  return parsed;
}

function main() {
  const command = process.argv[2];

  if (command !== "patch") {
    console.error('Usage: node version.js patch');
    process.exit(1);
  }

  const versionJson = readJson(versionJsonPath);
  const nextVersion = bumpPatch(versionJson.version);
  const now = new Date().toISOString();

  versionJson.version = formatDisplayVersion(nextVersion);
  versionJson.updatedAt = now;

  // Keep npm metadata stable so Docker can reuse the dependency layer between releases.
  writeJson(versionJsonPath, versionJson);

  console.log(`Bumped version to ${versionJson.version}`);
}

main();
