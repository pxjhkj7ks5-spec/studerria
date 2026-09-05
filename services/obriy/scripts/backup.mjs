import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
const [mode, file] = process.argv.slice(2),
  key = process.env.OBRIY_BACKUP_KEY;
if (
  !["backup", "restore"].includes(mode) ||
  !file ||
  !/^[a-f\d]{64}$/i.test(key ?? "")
)
  throw new Error(
    "Usage: OBRIY_BACKUP_KEY=<separate 32-byte hex key> node scripts/backup.mjs backup|restore FILE; PostgreSQL uses PG* environment",
  );
if (mode === "restore" && process.env.OBRIY_RESTORE_ALLOW !== "true")
  throw new Error(
    "Restore requires OBRIY_RESTORE_ALLOW=true and an empty, explicitly selected destination database",
  );
const run = (binary, args, input) =>
  new Promise((resolve, reject) => {
    const child = spawn(binary, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
    });
    const chunks = [];
    let size = 0;
    child.stdout.on("data", (chunk) => {
      size += chunk.length;
      if (size > 64 * 1024 * 1024) child.kill();
      else chunks.push(chunk);
    });
    child.stderr.resume();
    child.on("error", () =>
      reject(new Error("PostgreSQL client is unavailable")),
    );
    child.on("close", (code) =>
      code === 0
        ? resolve(Buffer.concat(chunks))
        : reject(
            new Error(
              "PostgreSQL operation failed; verify destination and permissions",
            ),
          ),
    );
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
if (mode === "backup") {
  const dump = await run("pg_dump", [
    "--format=custom",
    "--schema=obriy",
    "--no-owner",
    "--no-acl",
  ]);
  const iv = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", Buffer.from(key, "hex"), iv);
  cipher.setAAD(Buffer.from("OBRIY-BACKUP-v1"));
  const encrypted = Buffer.concat([cipher.update(dump), cipher.final()]);
  await writeFile(
    file,
    Buffer.concat([Buffer.from("OBR1"), iv, cipher.getAuthTag(), encrypted]),
    { flag: "wx", mode: 0o600 },
  );
  console.log(
    "Encrypted Obriy schema backup created. Store its key separately and verify restoration.",
  );
} else {
  const data = await readFile(file);
  if (data.subarray(0, 4).toString() !== "OBR1")
    throw new Error("Unknown backup format");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    Buffer.from(key, "hex"),
    data.subarray(4, 16),
  );
  decipher.setAAD(Buffer.from("OBRIY-BACKUP-v1"));
  decipher.setAuthTag(data.subarray(16, 32));
  let dump;
  try {
    dump = Buffer.concat([
      decipher.update(data.subarray(32)),
      decipher.final(),
    ]);
  } catch {
    throw new Error("Backup authentication failed; database untouched");
  }
  await run(
    "pg_restore",
    [
      "--dbname",
      process.env.PGDATABASE ?? "obriy",
      "--no-owner",
      "--no-acl",
      "--exit-on-error",
      "--single-transaction",
    ],
    dump,
  );
  console.log(
    "Obriy schema restored. Check encrypted zones using the original application key before enabling delivery.",
  );
}
