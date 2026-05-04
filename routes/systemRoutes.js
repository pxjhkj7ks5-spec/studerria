function registerSystemRoutes(app, deps) {
  const {
    canAccessOperationalDetails,
    getInitStatus,
    getInitError,
    sessionHealthState,
    sessionHealthProbeIntervalSeconds,
    appVersion,
    buildStamp,
    ensureDbReady,
    env = process.env,
  } = deps;

  app.get('/_health', (req, res) => {
    const initStatus = getInitStatus();
    const initError = getInitError();
    const dbStatus = initStatus === 'ok' ? 'ok' : (initStatus === 'error' ? 'fail' : 'starting');
    const sessionStatus = sessionHealthState.ok ? 'ok' : 'fail';
    const status = dbStatus === 'fail' || sessionStatus === 'fail'
      ? 'degraded'
      : (dbStatus === 'starting' ? 'starting' : 'ok');
    const strictMode = String(req.query.strict || '') === '1';
    const detailedMode = canAccessOperationalDetails(req);
    const httpStatus = strictMode && status !== 'ok' ? 503 : 200;
    res.setHeader('Cache-Control', 'no-store');
    const payload = {
      status,
      healthy: status === 'ok',
    };
    if (detailedMode) {
      payload.db = {
        initStatus,
        status: dbStatus,
        error: initError ? String(initError.message || initError) : null,
      };
      payload.session = {
        ok: sessionHealthState.ok,
        status: sessionStatus,
        table: sessionHealthState.table,
        checks: sessionHealthState.checks,
        failures: sessionHealthState.failures,
        probe_interval_seconds: sessionHealthProbeIntervalSeconds,
        last_checked_at: sessionHealthState.lastCheckedAt,
        last_ok_at: sessionHealthState.lastOkAt,
        last_error_at: sessionHealthState.lastErrorAt,
        last_error: sessionHealthState.lastError,
        last_duration_ms: sessionHealthState.lastDurationMs,
      };
    }
    res.status(httpStatus).json(payload);
  });

  app.get('/__version', (req, res) => {
    if (!canAccessOperationalDetails(req)) {
      return res.status(404).send('Not found');
    }
    res.setHeader('Cache-Control', 'no-store');
    res.json({
      version: appVersion,
      buildStamp,
      node: process.version,
    });
  });

  app.post('/_bootstrap', async (req, res) => {
    const token = String(env.BOOTSTRAP_TOKEN || '').trim();
    const provided = String(req.get('x-bootstrap-token') || '').trim();
    if (!token || provided !== token) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }
    try {
      await ensureDbReady();
      return res.json({ ok: true, initStatus: getInitStatus() });
    } catch (err) {
      return res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });
}

module.exports = {
  registerSystemRoutes,
};
