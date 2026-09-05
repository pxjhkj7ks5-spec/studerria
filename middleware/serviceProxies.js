const { createProxyMiddleware } = require('http-proxy-middleware');

const CHARREDMAP_BASE_PATH = '/charredmap';
const CHINAMAP_BASE_PATH = '/china-map';
const NARADADRUK_BASE_PATH = '/naradadruk';
const YKG_BASE_PATH = '/ykg';
const WITHLFORL_BASE_PATH = '/withlforl';
const OSIX_BASE_PATH = '/osix';
const OBRIY_BASE_PATH = '/obriy';
const SHIELDLINE_BASE_PATH = '/shieldline';
const DEFAULT_SLASHTG_BASE_PATH = '/tg';

function normalizePublicHost(value) {
  const candidate = String(value || '').trim().toLowerCase();
  if (!candidate) return '';

  try {
    const parsed = new URL(`http://${candidate}`);
    if (
      parsed.username
      || parsed.password
      || parsed.pathname !== '/'
      || parsed.search
      || parsed.hash
    ) {
      return '';
    }
    return parsed.hostname.toLowerCase();
  } catch {
    return '';
  }
}

function getRequestHostname(req) {
  const hostname = typeof req.hostname === 'string' ? req.hostname : '';
  const hostHeader = typeof req.headers?.host === 'string' ? req.headers.host : '';
  return normalizePublicHost(hostname || hostHeader);
}

function isPublicHostRequest(req, publicHost) {
  return Boolean(publicHost) && getRequestHostname(req) === publicHost;
}

function buildNaradaDrukRedirectUrl(req, publicHost) {
  const originalUrl = String(req.originalUrl || req.url || NARADADRUK_BASE_PATH);
  const queryIndex = originalUrl.indexOf('?');
  const pathname = queryIndex >= 0 ? originalUrl.slice(0, queryIndex) : originalUrl;
  const query = queryIndex >= 0 ? originalUrl.slice(queryIndex) : '';
  const suffix = pathname === NARADADRUK_BASE_PATH
    ? '/'
    : pathname.slice(NARADADRUK_BASE_PATH.length) || '/';
  return `https://${publicHost}${suffix}${query}`;
}

function redirectPermanent(res, location) {
  if (typeof res.redirect === 'function') {
    return res.redirect(308, location);
  }
  res.statusCode = 308;
  res.setHeader('Location', location);
  return res.end();
}

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

function createServiceProxy({ target, basePath, serviceName, logLabel, logger, forwardResolvedClientIp = false }) {
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
      proxyReq(proxyReq, req) {
        proxyReq.setHeader('x-forwarded-prefix', basePath);
        if (forwardResolvedClientIp) {
          const resolvedClientIp = typeof req.ip === 'string' ? req.ip.trim() : '';
          if (resolvedClientIp) {
            proxyReq.setHeader('x-studerria-client-ip', resolvedClientIp);
            proxyReq.setHeader(
              'x-studerria-client-ip-source',
              Array.isArray(req.ips) && req.ips.length > 0 ? 'trusted-forwarded' : 'socket-peer'
            );
          } else {
            proxyReq.removeHeader('x-studerria-client-ip');
            proxyReq.setHeader('x-studerria-client-ip-source', 'missing');
          }
        }
      },
    },
  });
}

function registerServiceProxies(app, deps = {}) {
  const env = deps.env || process.env;
  const logger = deps.logger || console;
  const charredmapProxyTarget = String(env.CHARREDMAP_PROXY_TARGET || '').trim();
  const chinaMapProxyTarget = String(env.CHINAMAP_PROXY_TARGET || '').trim();
  const naradadrukProxyTarget = String(env.NARADADRUK_PROXY_TARGET || '').trim();
  const ykgProxyTarget = String(env.YKG_PROXY_TARGET || '').trim();
  const naradadrukPublicHost = normalizePublicHost(env.NARADADRUK_PUBLIC_HOST);
  const withlforlProxyTarget = String(env.WITHLFORL_PROXY_TARGET || '').trim();
  const osixProxyTarget = String(env.OSIX_PROXY_TARGET || '').trim();
  const obriyProxyTarget = String(env.OBRIY_PROXY_TARGET || '').trim();
  const shieldlineProxyTarget = String(env.SHIELDLINE_PROXY_TARGET || '').trim();
  const slashtgProxyTarget = String(env.SLASHTG_PROXY_TARGET || '').trim();
  const slashtgBasePath = String(env.SLASHTG_BASE_PATH || DEFAULT_SLASHTG_BASE_PATH).trim() || DEFAULT_SLASHTG_BASE_PATH;

  const charredmapProxy = createServiceProxy({
    target: charredmapProxyTarget,
    basePath: CHARREDMAP_BASE_PATH,
    serviceName: 'Charredmap',
    logLabel: 'Charredmap',
    logger,
  });
  const chinaMapProxy = createServiceProxy({
    target: chinaMapProxyTarget,
    basePath: CHINAMAP_BASE_PATH,
    serviceName: 'China Map',
    logLabel: 'China Map',
    logger,
  });
  const naradadrukProxy = createServiceProxy({
    target: naradadrukProxyTarget,
    basePath: NARADADRUK_BASE_PATH,
    serviceName: 'Narada Druk',
    logLabel: 'Narada Druk',
    logger,
    forwardResolvedClientIp: true,
  });
  const naradadrukPublicHostProxy = createServiceProxy({
    target: naradadrukProxyTarget,
    basePath: '',
    serviceName: 'Narada Druk',
    logLabel: 'Narada Druk public host',
    logger,
    forwardResolvedClientIp: true,
  });
  const ykgProxy = createServiceProxy({
    target: ykgProxyTarget,
    basePath: YKG_BASE_PATH,
    serviceName: 'YKG Store',
    logLabel: 'YKG Store',
    logger,
    forwardResolvedClientIp: true,
  });
  const withlforlProxy = createServiceProxy({
    target: withlforlProxyTarget,
    basePath: WITHLFORL_BASE_PATH,
    serviceName: 'Withlforl',
    logLabel: 'Withlforl',
    logger,
  });
  const obriyProxy = createServiceProxy({ target: obriyProxyTarget, basePath: OBRIY_BASE_PATH, serviceName: 'Obriy', logLabel: 'Obriy', logger });
  const osixProxy = createServiceProxy({
    target: osixProxyTarget,
    basePath: OSIX_BASE_PATH,
    serviceName: 'OSIX',
    logLabel: 'OSIX',
    logger,
  });
  const shieldlineProxy = createServiceProxy({
    target: shieldlineProxyTarget,
    basePath: SHIELDLINE_BASE_PATH,
    serviceName: 'Shieldline',
    logLabel: 'Shieldline',
    logger,
  });
  const slashtgProxy = createServiceProxy({
    target: slashtgProxyTarget,
    basePath: slashtgBasePath,
    serviceName: 'Slash TG',
    logLabel: 'Slash TG',
    logger,
  });
  app.use((req, res, next) => {
    if (!isPublicHostRequest(req, naradadrukPublicHost)) {
      return next();
    }
    if (isServiceRequest(req, NARADADRUK_BASE_PATH)) {
      return redirectPermanent(
        res,
        buildNaradaDrukRedirectUrl(req, naradadrukPublicHost),
      );
    }
    if (!naradadrukPublicHostProxy) {
      return respondServiceUnavailable(res, 'Narada Druk', 404);
    }
    return naradadrukPublicHostProxy(req, res, next);
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
    if (!isServiceRequest(req, CHINAMAP_BASE_PATH)) {
      return next();
    }
    if (!chinaMapProxy) {
      return respondServiceUnavailable(res, 'China Map', 404);
    }
    return chinaMapProxy(req, res, next);
  });

  app.use((req, res, next) => {
    if (!isServiceRequest(req, NARADADRUK_BASE_PATH)) {
      return next();
    }
    if (naradadrukPublicHost) {
      return redirectPermanent(
        res,
        buildNaradaDrukRedirectUrl(req, naradadrukPublicHost),
      );
    }
    if (!naradadrukProxy) {
      return respondServiceUnavailable(res, 'Narada Druk', 404);
    }
    return naradadrukProxy(req, res, next);
  });

  app.use((req, res, next) => {
    if (!isServiceRequest(req, YKG_BASE_PATH)) {
      return next();
    }
    if (!ykgProxy) {
      return respondServiceUnavailable(res, 'YKG Store', 404);
    }
    return ykgProxy(req, res, next);
  });

  app.use((req, res, next) => {
    if (!isServiceRequest(req, WITHLFORL_BASE_PATH)) {
      return next();
    }
    if (!withlforlProxy) {
      return respondServiceUnavailable(res, 'Withlforl', 404);
    }
    return withlforlProxy(req, res, next);
  });

  app.use((req, res, next) => {
    if (!isServiceRequest(req, OBRIY_BASE_PATH)) return next();
    if (!obriyProxy) return respondServiceUnavailable(res, 'Obriy', 404);
    return obriyProxy(req, res, next);
  });

  app.use((req, res, next) => {
    if (!isServiceRequest(req, OSIX_BASE_PATH)) {
      return next();
    }
    if (!osixProxy) {
      return respondServiceUnavailable(res, 'OSIX', 404);
    }
    return osixProxy(req, res, next);
  });

  app.use((req, res, next) => {
    if (!isServiceRequest(req, SHIELDLINE_BASE_PATH)) {
      return next();
    }
    if (!shieldlineProxy) {
      return respondServiceUnavailable(res, 'Shieldline', 404);
    }
    return shieldlineProxy(req, res, next);
  });

  app.use((req, res, next) => {
    if (!isServiceRequest(req, slashtgBasePath)) {
      return next();
    }
    if (!slashtgProxy) {
      return respondServiceUnavailable(res, 'Slash TG', 404);
    }
    return slashtgProxy(req, res, next);
  });

}

module.exports = {
  buildNaradaDrukRedirectUrl,
  normalizePublicHost,
  registerServiceProxies,
};
