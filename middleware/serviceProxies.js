const { createProxyMiddleware } = require('http-proxy-middleware');

const CHARREDMAP_BASE_PATH = '/charredmap';
const NARADADRUK_BASE_PATH = '/naradadruk';

function isServiceRequest(req, basePath) {
  const pathname = typeof req.path === 'string' ? req.path : String(req.url || '').split('?')[0];
  return pathname === basePath || pathname.startsWith(`${basePath}/`);
}

function respondServiceUnavailable(res, serviceName, statusCode = 503) {
  if (!res || res.headersSent) return;
  const body = statusCode === 404 ? 'Not found' : `${serviceName} is temporarily unavailable.`;
  if (typeof res.status === 'function') {
    res.status(statusCode);
  } else {
    res.statusCode = statusCode;
  }
  if (typeof res.setHeader === 'function') {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  }
  if (typeof res.type === 'function') {
    res.type('text/plain; charset=utf-8');
  }
  if (typeof res.send === 'function') {
    res.send(body);
    return;
  }
  if (typeof res.end === 'function') {
    res.end(body);
  }
}

function createServiceProxy({ target, basePath, serviceName, logLabel, logger }) {
  if (!/^https?:\/\//i.test(target)) return null;
  return createProxyMiddleware({
    target,
    changeOrigin: false,
    xfwd: true,
    ws: false,
    proxyTimeout: 30000,
    timeout: 30000,
    on: {
      error(err, req, res) {
        logger.error(`${logLabel} proxy error`, err);
        respondServiceUnavailable(res, serviceName, 503);
      },
      proxyReq(proxyReq) {
        proxyReq.setHeader('x-forwarded-prefix', basePath);
      },
    },
  });
}

function registerServiceProxies(app, deps = {}) {
  const env = deps.env || process.env;
  const logger = deps.logger || console;
  const charredmapProxyTarget = String(env.CHARREDMAP_PROXY_TARGET || '').trim();
  const naradadrukProxyTarget = String(env.NARADADRUK_PROXY_TARGET || '').trim();

  const charredmapProxy = createServiceProxy({
    target: charredmapProxyTarget,
    basePath: CHARREDMAP_BASE_PATH,
    serviceName: 'Charredmap',
    logLabel: 'Charredmap',
    logger,
  });
  const naradadrukProxy = createServiceProxy({
    target: naradadrukProxyTarget,
    basePath: NARADADRUK_BASE_PATH,
    serviceName: 'Narada Druk',
    logLabel: 'Narada Druk',
    logger,
  });

  app.use((req, res, next) => {
    if (!isServiceRequest(req, CHARREDMAP_BASE_PATH)) {
      return next();
    }
    if (!charredmapProxy) {
      return respondServiceUnavailable(res, 'Charredmap', 404);
    }
    return charredmapProxy(req, res, next);
  });

  app.use((req, res, next) => {
    if (!isServiceRequest(req, NARADADRUK_BASE_PATH)) {
      return next();
    }
    if (!naradadrukProxy) {
      return respondServiceUnavailable(res, 'Narada Druk', 404);
    }
    return naradadrukProxy(req, res, next);
  });
}

module.exports = {
  registerServiceProxies,
};
