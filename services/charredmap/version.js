#!/usr/bin/env node

const fs = require("node:fs");
const path = require("node:path");

const rootDir = __dirname;
const packageJsonPath = path.join(rootDir, "package.json");
const packageLockPath = path.join(rootDir, "package-lock.json");
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

function formatSemver({ major, minor, patch }) {
  return `${major}.${minor}.${patch}`;
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

  const packageJson = readJson(packageJsonPath);
  const versionJson = readJson(versionJsonPath);
  const nextVersion = bumpPatch(versionJson.version);
  const now = new Date().toISOString();

  versionJson.version = formatDisplayVersion(nextVersion);
  versionJson.updatedAt = now;

  packageJson.version = formatSemver(nextVersion);

  writeJson(versionJsonPath, versionJson);
  writeJson(packageJsonPath, packageJson);

  if (fs.existsSync(packageLockPath)) {
    const packageLock = readJson(packageLockPath);
    packageLock.version = packageJson.version;

    if (packageLock.packages?.[""]) {
      packageLock.packages[""].version = packageJson.version;
    }

    writeJson(packageLockPath, packageLock);
  }

  console.log(`Bumped version to ${versionJson.version}`);
}

main();
