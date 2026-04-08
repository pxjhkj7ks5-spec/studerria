function resolveTrustProxySetting(rawValue, { isProd = false } = {}) {
  if (!rawValue) return isProd ? 1 : false;
  const normalized = String(rawValue).trim().toLowerCase();
  if (['false', '0', 'off', 'none'].includes(normalized)) return false;
  if (['true', '1', 'on'].includes(normalized)) return 1;
  const numeric = Number(rawValue);
  if (Number.isFinite(numeric) && numeric >= 0) {
    return Math.floor(numeric);
  }
  return rawValue;
}

function resolveDbSslConfig({ enabled = false, ca = '' } = {}) {
  if (!enabled) return false;
  const normalizedCa = String(ca || '').replace(/\\n/g, '\n');
  if (!normalizedCa) {
    throw new Error('DB_SSL=true requires DB_SSL_CA so the Postgres certificate can be verified.');
  }
  return {
    ca: normalizedCa,
    rejectUnauthorized: true,
  };
}

function resolveSessionSecret(rawValue, { isProd = false, fallback = 'dev-secret-change-me' } = {}) {
  const normalizedSecret = String(rawValue || '').trim();
  if (isProd && !normalizedSecret) {
    throw new Error('SESSION_SECRET must be set in production.');
  }
  return {
    secret: normalizedSecret || fallback,
    usedFallback: !normalizedSecret,
  };
}

function isLoopbackIpAddress(rawIp) {
  const normalized = String(rawIp || '')
    .trim()
    .toLowerCase()
    .replace(/^::ffff:/, '');
  return normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost';
}

function canAccessOperationalDetails({
  providedToken = '',
  statusAccessToken = '',
  isAdmin = false,
  isDeanery = false,
  clientIp = '',
} = {}) {
  const normalizedProvidedToken = String(providedToken || '').trim();
  const normalizedStatusAccessToken = String(statusAccessToken || '').trim();
  if (
    normalizedStatusAccessToken
    && normalizedProvidedToken
    && normalizedProvidedToken.length === normalizedStatusAccessToken.length
    && require('crypto').timingSafeEqual(
      Buffer.from(normalizedProvidedToken),
      Buffer.from(normalizedStatusAccessToken),
    )
  ) {
    return true;
  }
  if (isAdmin || isDeanery) {
    return true;
  }
  return isLoopbackIpAddress(clientIp);
}

module.exports = {
  canAccessOperationalDetails,
  isLoopbackIpAddress,
  resolveDbSslConfig,
  resolveSessionSecret,
  resolveTrustProxySetting,
};
