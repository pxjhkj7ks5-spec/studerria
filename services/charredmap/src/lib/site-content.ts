import { readFile } from "node:fs/promises";
import path from "node:path";

export type VersionInfo = {
  name: string;
  version: string;
  updatedAt: string;
};

export type ChangelogEntry = {
  hash: string;
  shortHash: string;
  message: string;
  date: string;
};

export type ChangelogPayload = {
  version: string;
  generatedAt: string;
  entries: ChangelogEntry[];
};

async function readJsonFile<T>(fileName: string, fallback: T): Promise<T> {
  try {
    const filePath = path.join(process.cwd(), fileName);
    const contents = await readFile(filePath, "utf8");
    return JSON.parse(contents) as T;
  } catch {
    return fallback;
  }
}

export async function getVersionInfo() {
  return readJsonFile<VersionInfo>("version.json", {
    name: "charredmap",
    version: "0.1.00",
    updatedAt: new Date(0).toISOString(),
  });
}

export async function getChangelog() {
  return readJsonFile<ChangelogPayload>("changelog.json", {
    version: "0.1.00",
    generatedAt: new Date(0).toISOString(),
    entries: [],
  });
}
