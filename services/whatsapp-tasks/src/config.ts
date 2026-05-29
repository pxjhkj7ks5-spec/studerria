export type AppConfig = {
  nodeEnv: string;
  port: number;
  basePath: string;
  publicUrl: string;
  database: {
    connectionString: string;
    host: string;
    port: number;
    user: string;
    password: string;
    database: string;
  };
  sessionSecret: string;
  devEmail: string;
  devPassword: string;
  workerEnabled: boolean;
  workerIntervalMs: number;
  whatsapp: {
    accessToken: string;
    phoneNumberId: string;
    verifyToken: string;
    appSecret: string;
    graphVersion: string;
  };
};

function envString(name: string, fallback = "") {
  const value = process.env[name];
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function envNumber(name: string, fallback: number) {
  const value = Number.parseInt(envString(name), 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function normalizeBasePath(value: string) {
  const trimmed = value.trim();
  if (!trimmed || trimmed === "/") return "";
  return `/${trimmed.replace(/^\/+|\/+$/g, "")}`;
}

export function loadConfig(): AppConfig {
  const basePath = normalizeBasePath(envString("WA_TASKS_BASE_PATH", "/wa-tasks"));
  return {
    nodeEnv: envString("NODE_ENV", "development"),
    port: envNumber("PORT", 8080),
    basePath,
    publicUrl: envString("WA_TASKS_PUBLIC_URL", "https://studerria.com/wa-tasks").replace(/\/+$/g, ""),
    database: {
      connectionString: envString("WA_TASKS_DATABASE_URL", envString("DATABASE_URL")),
      host: envString("WA_TASKS_DB_HOST", "127.0.0.1"),
      port: envNumber("WA_TASKS_DB_PORT", 5432),
      user: envString("WA_TASKS_DB_USER", "wa_tasks"),
      password: envString("WA_TASKS_DB_PASSWORD", "wa_tasks_local"),
      database: envString("WA_TASKS_DB_NAME", "wa_tasks"),
    },
    sessionSecret: envString("WA_TASKS_SESSION_SECRET", "change-me-wa-tasks-session-secret-change-this"),
    devEmail: envString("WA_TASKS_DEV_EMAIL", "dev@studerria.local").toLowerCase(),
    devPassword: envString("WA_TASKS_DEV_PASSWORD", "change-me-wa-tasks-dev"),
    workerEnabled: envString("WA_TASKS_WORKER_ENABLED", "true") !== "false",
    workerIntervalMs: envNumber("WA_TASKS_WORKER_INTERVAL_MS", 60_000),
    whatsapp: {
      accessToken: envString("WHATSAPP_ACCESS_TOKEN"),
      phoneNumberId: envString("WHATSAPP_PHONE_NUMBER_ID"),
      verifyToken: envString("WHATSAPP_VERIFY_TOKEN"),
      appSecret: envString("WHATSAPP_APP_SECRET"),
      graphVersion: envString("WHATSAPP_GRAPH_VERSION", "v24.0"),
    },
  };
}

export function withBasePath(config: Pick<AppConfig, "basePath">, path: string) {
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  return `${config.basePath}${cleanPath}`;
}
