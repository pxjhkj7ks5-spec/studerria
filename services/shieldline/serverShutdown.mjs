export function installShutdown(server, shutdownTelemetry, { timeoutMs = 45000, exit = code => process.exit(code) } = {}) {
  let stopping = false;
  const shutdown = () => {
    if (stopping) return;
    stopping = true;
    const deadline = setTimeout(() => {
      console.error('Shieldline shutdown timed out');
      exit(1);
    }, timeoutMs);
    server.close(async error => {
      try {
        if (error) throw error;
        await shutdownTelemetry();
        clearTimeout(deadline);
        exit(0);
      } catch {
        clearTimeout(deadline);
        console.error('Shieldline shutdown failed');
        exit(1);
      }
    });
    server.closeIdleConnections?.();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  return () => {
    process.off('SIGTERM', shutdown);
    process.off('SIGINT', shutdown);
  };
}
