'use strict';

const { loadConfig } = require('./config');
const { createPool, migrate } = require('./db');
const { OsintStore } = require('./store');
const { createCollectors } = require('./collectors');
const { RunExecutor } = require('./jobs');
const { createApp } = require('./app');

async function main() {
  const config = loadConfig();
  const pool = createPool(config);
  await migrate(pool);
  const store = new OsintStore(pool);
  const recovered = await store.recoverInterruptedRuns();
  const collectors = createCollectors(config);
  const executor = new RunExecutor({ store, collectors, config });
  const app = createApp({ config, store, collectors, executor });
  const server = app.listen(config.port, '0.0.0.0', () => {
    console.info(JSON.stringify({ event: 'osint_start', port: config.port, recovered_runs: recovered, collectors: Array.from(collectors.keys()) }));
  });
  const shutdown = (signal) => {
    console.info(JSON.stringify({ event: 'osint_shutdown', signal }));
    server.close(async () => {
      await pool.end();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 15000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  const retentionTimer = setInterval(() => store.purgeExpired(config.retentionDays).catch((error) => {
    console.error(JSON.stringify({ event: 'osint_retention_failed', error: String(error.message || error).slice(0, 160) }));
  }), 24 * 60 * 60 * 1000);
  retentionTimer.unref();
}

main().catch((error) => {
  console.error(JSON.stringify({ event: 'osint_start_failed', error: String(error.message || error).slice(0, 200) }));
  process.exit(1);
});
