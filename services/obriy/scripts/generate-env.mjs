import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
const destination = process.argv[2] ?? ".env";
let source = await readFile(".env.example", "utf8");
for (const key of [
  "OBRIY_ENCRYPTION_KEY",
  "OBRIY_ADMIN_TOKEN",
  "OBRIY_METRICS_TOKEN",
  "OBRIY_TELEGRAM_WEBHOOK_SECRET",
])
  source = source.replace(
    `${key}=\n`,
    `${key}=${randomBytes(32).toString("hex")}\n`,
  );
await writeFile(destination, source, { flag: "wx", mode: 0o600 });
console.log(
  "Private environment file created. Existing files are never overwritten.",
);
