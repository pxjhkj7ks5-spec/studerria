import { loadConfig } from "./config.js";
import { Store } from "./store.js";
import { Runtime } from "./runtime.js";
import { buildServer } from "./server.js";
import { logEvent } from "./security.js";
async function main() {
  const config = loadConfig(),
    store = new Store(config);
  let stop: ((fatal?: boolean) => Promise<void>) | undefined;
  const runtime = new Runtime(config, store, () => {
    void stop?.(true);
  });
  await store.migrate();
  const server = await buildServer(config, store, runtime);
  let stopping = false;
  stop = async (fatal = false) => {
    if (stopping) return;
    stopping = true;
    const deadline = setTimeout(() => process.exit(1), 40000);
    deadline.unref();
    await Promise.all([server.close(), runtime.stop()]);
    await store.close();
    clearTimeout(deadline);
    if (fatal) process.exit(1);
  };
  await runtime.start();
  await server.listen({ host: "0.0.0.0", port: config.PORT });
  logEvent("obriy_started", {
    configured: config.configured,
    version: config.OBRIY_RELEASE_VERSION,
  });
  process.on("SIGTERM", () => {
    void stop?.();
  });
  process.on("SIGINT", () => {
    void stop?.();
  });
}
main().catch(() => {
  logEvent("startup_failed");
  setTimeout(() => process.exit(1), 100);
});
