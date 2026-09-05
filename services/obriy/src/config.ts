import { z } from "zod";

const integer = (fallback: number, min: number, max: number) =>
  z.coerce.number().int().min(min).max(max).default(fallback);
const schema = z.object({
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
  PORT: integer(8080, 1, 65535),
  OBRIY_BASE_PATH: z
    .string()
    .regex(/^\/[a-z0-9/-]*$/)
    .default("/obriy"),
  OBRIY_PUBLIC_URL: z.string().url().default("http://localhost:8080/obriy"),
  OBRIY_DB_HOST: z.string().default("127.0.0.1"),
  OBRIY_DB_PORT: integer(5432, 1, 65535),
  OBRIY_DB_NAME: z.string().default("obriy"),
  OBRIY_DB_USER: z.string().default("obriy"),
  OBRIY_DB_PASSWORD: z.string().default(""),
  OBRIY_DATABASE_URL: z.string().default(""),
  OBRIY_ENCRYPTION_KEY: z.string().default(""),
  OBRIY_ADMIN_TOKEN: z.string().default(""),
  OBRIY_TELEGRAM_BOT_TOKEN: z.string().default(""),
  OBRIY_TELEGRAM_BOT_USERNAME: z
    .string()
    .regex(/^$|^[A-Za-z0-9_]{5,32}$/)
    .default(""),
  OBRIY_TELEGRAM_WEBHOOK_SECRET: z
    .string()
    .regex(/^$|^[A-Za-z0-9_-]{32,256}$/)
    .default(""),
  OBRIY_TELEGRAM_MODE: z
    .enum(["polling", "webhook", "disabled"])
    .default("polling"),
  OBRIY_ALERTS_TOKEN: z.string().default(""),
  OBRIY_NEPTUN_WS_URL: z
    .string()
    .url()
    .default("wss://neptun.in.ua/api/v1/stream"),
  OBRIY_NEPTUN_REST_URL: z
    .string()
    .url()
    .default("https://neptun.in.ua/api/v1/threats"),
  OBRIY_ALERTS_URL: z
    .string()
    .url()
    .default("https://api.alerts.in.ua/v1/alerts/active.json"),
  OBRIY_NEPTUN_POLL_MS: integer(15000, 5000, 300000),
  OBRIY_HEARTBEAT_MS: integer(60000, 30000, 300000),
  OBRIY_ALERTS_POLL_MS: integer(15000, 12000, 300000),
  OBRIY_DEFAULT_RADIUS_KM: integer(10, 1, 100),
  OBRIY_RETENTION_DAYS: integer(30, 1, 90),
  OBRIY_RAW_RETENTION_HOURS: integer(24, 1, 72),
  OBRIY_SESSION_HOURS: integer(12, 1, 168),
  OBRIY_COLLECTORS_ENABLED: z.enum(["true", "false"]).default("true"),
  OBRIY_AIRSIGMA_SOURCE_IDENTIFIER: z.string().default(""),
  OBRIY_METRICS_TOKEN: z.string().default(""),
  OBRIY_RELEASE_VERSION: z.string().default("0.1.0"),
});
export type Config = z.infer<typeof schema> & {
  configured: boolean;
  base: string;
};
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success)
    throw new Error(
      `Invalid configuration fields: ${parsed.error.issues.map((x) => x.path.join(".")).join(", ")}`,
    );
  const c = parsed.data;
  if (c.OBRIY_ENCRYPTION_KEY && !/^[a-f0-9]{64}$/i.test(c.OBRIY_ENCRYPTION_KEY))
    throw new Error(
      "OBRIY_ENCRYPTION_KEY must be 32 random bytes encoded as hex",
    );
  if (c.OBRIY_ADMIN_TOKEN && c.OBRIY_ADMIN_TOKEN.length < 32)
    throw new Error("OBRIY_ADMIN_TOKEN needs at least 32 random characters");
  if (
    c.OBRIY_TELEGRAM_BOT_TOKEN &&
    !/^\d+:[A-Za-z0-9_-]{20,}$/.test(c.OBRIY_TELEGRAM_BOT_TOKEN)
  )
    throw new Error("Invalid Telegram bot token format");
  if (
    c.OBRIY_TELEGRAM_MODE === "webhook" &&
    c.OBRIY_TELEGRAM_BOT_TOKEN &&
    !c.OBRIY_TELEGRAM_WEBHOOK_SECRET
  )
    throw new Error("Webhook mode requires secret");
  for (const value of [
    c.OBRIY_NEPTUN_REST_URL,
    c.OBRIY_ALERTS_URL,
    c.OBRIY_NEPTUN_WS_URL,
  ]) {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash)
      throw new Error("Source URL cannot contain credentials or query");
    if (
      c.NODE_ENV === "production" &&
      !["https:", "wss:"].includes(url.protocol)
    )
      throw new Error("Production sources require TLS");
  }
  if (
    c.NODE_ENV === "production" &&
    new URL(c.OBRIY_PUBLIC_URL).protocol !== "https:"
  )
    throw new Error("Production public URL requires HTTPS");
  return {
    ...c,
    configured: Boolean(c.OBRIY_ENCRYPTION_KEY && c.OBRIY_ADMIN_TOKEN),
    base: c.OBRIY_BASE_PATH.replace(/\/$/, ""),
  };
}
