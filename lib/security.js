const { createHash } = require('crypto');
const net = require('net');

const ADMIN_IP_ALLOWLIST_LIMIT = 120;
const ADMIN_IP_RULE_MAX_LENGTH = 64;
const TRUSTED_ADMIN_IP_RISK_BONUS = 30;
const SESSION_SECURITY_DEFAULTS = {
  idleTimeoutMinutes: 14 * 24 * 60,
  absoluteTimeoutHours: 28 * 24,
  stepUpReauthMinutes: 15,
};
const SECURITY_RISK_THRESHOLDS_DEFAULTS = {
  low: 35,
  medium: 65,
  high: 95,
};
const SECURITY_RISK_RULE_WEIGHTS = {
  trusted_admin_ip_bonus: TRUSTED_ADMIN_IP_RISK_BONUS,
  login_new_ip_and_device: 35,
  login_unusual_geo: 22,
  login_impossible_travel: 32,
  login_environment_shift: 18,
  behavior_admin_burst: 30,
  behavior_fast_admin_flow: 16,
  admin_role_changed: 26,
  admin_permissions_changed: 26,
  admin_security_settings_changed: 28,
  admin_retention_policy_changed: 24,
  admin_rollback: 30,
  bulk_delete: 24,
  bulk_import_export: 18,
  auth_failure_spike: 18,
  shared_session: 48,
  shared_ip: 18,
  shared_device: 20,
  registration_ip_cluster: 34,
  registration_device_cluster: 26,
};

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
  const normalized = normalizeIpAddress(rawIp);
  return normalized === '127.0.0.1' || normalized === '::1' || normalized === 'localhost';
}

function normalizeIpAddress(rawIp) {
  const normalized = String(rawIp || '')
    .trim()
    .toLowerCase()
    .replace(/^::ffff:/, '');
  return normalized || null;
}

function normalizeUserAgent(rawValue, maxLength = 500) {
  const normalized = String(rawValue || '').trim().replace(/\s+/g, ' ');
  if (!normalized) return null;
  return normalized.slice(0, maxLength);
}

function parseIpv4ToInt(rawIp) {
  const normalized = normalizeIpAddress(rawIp);
  if (!normalized) return null;
  const parts = normalized.split('.');
  if (parts.length !== 4) return null;
  let acc = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (!Number.isInteger(value) || value < 0 || value > 255) return null;
    acc = (acc << 8) + value;
  }
  return acc >>> 0;
}

function parseIpv4CidrRule(rawRule) {
  const value = String(rawRule || '').trim();
  const segments = value.split('/');
  if (segments.length !== 2) return null;
  const ipInt = parseIpv4ToInt(segments[0]);
  if (ipInt === null) return null;
  const prefix = Number(segments[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0);
  return {
    type: 'cidr',
    raw: value,
    normalized: `${normalizeIpAddress(segments[0])}/${prefix}`,
    network: ipInt & mask,
    mask,
    prefix,
  };
}

function isValidIpv4Octet(rawValue) {
  if (!/^\d{1,3}$/.test(String(rawValue || ''))) return false;
  const value = Number(rawValue);
  return Number.isInteger(value) && value >= 0 && value <= 255;
}

function parseIpv4WildcardRule(rawRule) {
  const value = String(rawRule || '').trim();
  if (!value.endsWith('*')) return null;
  const segments = value.split('.');
  const starIndex = segments.indexOf('*');
  if (starIndex === -1 || starIndex !== segments.length - 1) return null;
  const fixedSegments = segments.slice(0, -1);
  if (!fixedSegments.length || fixedSegments.length > 3) return null;
  if (!fixedSegments.every(isValidIpv4Octet)) return null;
  return {
    type: 'wildcard',
    raw: value,
    normalized: `${fixedSegments.join('.')}.*`,
    prefix: `${fixedSegments.join('.')}.`,
  };
}

function buildAdminIpRule(rawRule) {
  const cleaned = String(rawRule || '').replace(/\s+/g, '').slice(0, ADMIN_IP_RULE_MAX_LENGTH);
  if (!cleaned) {
    return { ok: false, raw: rawRule, reason: 'empty' };
  }
  if (cleaned.includes('/')) {
    const cidrRule = parseIpv4CidrRule(cleaned);
    if (!cidrRule) {
      return { ok: false, raw: rawRule, reason: 'invalid_cidr' };
    }
    return { ok: true, rule: cidrRule };
  }
  if (cleaned.endsWith('*')) {
    const wildcardRule = parseIpv4WildcardRule(cleaned);
    if (!wildcardRule) {
      return { ok: false, raw: rawRule, reason: 'invalid_wildcard' };
    }
    return { ok: true, rule: wildcardRule };
  }
  const normalizedIp = normalizeIpAddress(cleaned);
  if (!normalizedIp || net.isIP(normalizedIp) < 1) {
    return { ok: false, raw: rawRule, reason: 'invalid_ip' };
  }
  return {
    ok: true,
    rule: {
      type: 'exact',
      raw: cleaned,
      normalized: normalizedIp,
    },
  };
}

function parseAdminIpAllowlist(rawValue, { limit = ADMIN_IP_ALLOWLIST_LIMIT } = {}) {
  const seen = new Set();
  const rules = [];
  const invalidEntries = [];
  String(rawValue || '')
    .split(/[\n,;]+/)
    .map((chunk) => String(chunk || '').trim())
    .filter(Boolean)
    .forEach((chunk) => {
      if (rules.length >= limit) return;
      const parsed = buildAdminIpRule(chunk);
      if (!parsed.ok) {
        invalidEntries.push({
          raw: String(chunk).slice(0, ADMIN_IP_RULE_MAX_LENGTH),
          reason: parsed.reason || 'invalid_rule',
        });
        return;
      }
      const key = String(parsed.rule.normalized || '').toLowerCase();
      if (!key || seen.has(key)) return;
      seen.add(key);
      rules.push(parsed.rule);
    });
  return {
    rules,
    invalidEntries,
  };
}

function formatAdminIpAllowlist(rawValue) {
  if (rawValue && typeof rawValue === 'object' && Array.isArray(rawValue.rules)) {
    return rawValue.rules.map((rule) => String(rule.normalized || '').trim()).filter(Boolean).join('\n');
  }
  return parseAdminIpAllowlist(rawValue).rules
    .map((rule) => String(rule.normalized || '').trim())
    .filter(Boolean)
    .join('\n');
}

function matchAdminIpAllowlist(rawIp, rawAllowlist) {
  const ip = normalizeIpAddress(rawIp);
  if (!ip) {
    return {
      matched: false,
      trustBonus: 0,
      rule: null,
      invalidEntries: [],
    };
  }
  const parsed = rawAllowlist && typeof rawAllowlist === 'object' && Array.isArray(rawAllowlist.rules)
    ? rawAllowlist
    : parseAdminIpAllowlist(rawAllowlist);
  const ipInt = parseIpv4ToInt(ip);
  for (const rule of parsed.rules) {
    if (!rule || !rule.type) continue;
    if (rule.type === 'exact' && rule.normalized === ip) {
      return {
        matched: true,
        trustBonus: TRUSTED_ADMIN_IP_RISK_BONUS,
        rule,
        invalidEntries: parsed.invalidEntries || [],
      };
    }
    if (rule.type === 'wildcard' && String(rule.prefix || '') && ip.startsWith(rule.prefix)) {
      return {
        matched: true,
        trustBonus: TRUSTED_ADMIN_IP_RISK_BONUS,
        rule,
        invalidEntries: parsed.invalidEntries || [],
      };
    }
    if (rule.type === 'cidr' && ipInt !== null && ((ipInt & rule.mask) === rule.network)) {
      return {
        matched: true,
        trustBonus: TRUSTED_ADMIN_IP_RISK_BONUS,
        rule,
        invalidEntries: parsed.invalidEntries || [],
      };
    }
  }
  return {
    matched: false,
    trustBonus: 0,
    rule: null,
    invalidEntries: parsed.invalidEntries || [],
  };
}

function buildDeviceFingerprint(rawValue) {
  const normalized = normalizeUserAgent(rawValue, 500);
  if (!normalized) return null;
  const compact = normalized.toLowerCase();
  const browserMatch = compact.match(/(edg|chrome|safari|firefox|opr|opera|trident|msie)\/[0-9.]+/);
  const osMatch = compact.match(/(windows nt [0-9.]+|android [0-9.]+|iphone os [0-9_]+|ipad; cpu os [0-9_]+|mac os x [0-9_]+|linux)/);
  const deviceMatch = compact.match(/(mobile|tablet|desktop)/);
  const browser = browserMatch ? browserMatch[1] : 'browser';
  const os = osMatch ? osMatch[1].replace(/\s+/g, '-') : 'os';
  const device = deviceMatch ? deviceMatch[1] : 'device';
  return `${browser}|${os}|${device}`.slice(0, 180);
}

function isPrivateIpv4(rawIp) {
  const ipInt = parseIpv4ToInt(rawIp);
  if (ipInt === null) return false;
  const a = (ipInt >>> 24) & 255;
  const b = (ipInt >>> 16) & 255;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

function buildGeoFingerprint(rawIp) {
  const ip = normalizeIpAddress(rawIp);
  if (!ip) return null;
  if (ip === '127.0.0.1' || ip === '::1') return 'loopback';
  if (parseIpv4ToInt(ip) !== null) {
    const parts = ip.split('.');
    if (isPrivateIpv4(ip)) {
      return `private:${parts.slice(0, 2).join('.')}`;
    }
    return `ipv4:${parts.slice(0, 2).join('.')}`;
  }
  if (net.isIP(ip) === 6) {
    const normalized = ip.replace(/::/g, ':');
    const segments = normalized.split(':').filter(Boolean).slice(0, 3);
    return segments.length ? `ipv6:${segments.join(':')}` : 'ipv6:unknown';
  }
  return 'unknown';
}

function evaluateImpossibleTravel({
  previousGeo = null,
  nextGeo = null,
  previousAt = null,
  nextAt = null,
  minHoursWindow = 6,
} = {}) {
  if (!previousGeo || !nextGeo || previousGeo === nextGeo) return false;
  const previousTs = previousAt ? new Date(previousAt).getTime() : NaN;
  const nextTs = nextAt ? new Date(nextAt).getTime() : NaN;
  if (!Number.isFinite(previousTs) || !Number.isFinite(nextTs) || nextTs <= previousTs) {
    return false;
  }
  return (nextTs - previousTs) <= (Math.max(1, Number(minHoursWindow) || 6) * 60 * 60 * 1000);
}

function normalizePositiveInt(rawValue, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number(rawValue);
  if (!Number.isFinite(parsed)) return fallback;
  const rounded = Math.floor(parsed);
  if (rounded < min) return fallback;
  if (rounded > max) return max;
  return rounded;
}

function normalizeSessionSecuritySettings(rawSettings = {}) {
  return {
    idleTimeoutMinutes: normalizePositiveInt(
      rawSettings.idleTimeoutMinutes,
      SESSION_SECURITY_DEFAULTS.idleTimeoutMinutes,
      { min: 5, max: 24 * 60 * 90 }
    ),
    absoluteTimeoutHours: normalizePositiveInt(
      rawSettings.absoluteTimeoutHours,
      SESSION_SECURITY_DEFAULTS.absoluteTimeoutHours,
      { min: 1, max: 24 * 90 }
    ),
    stepUpReauthMinutes: normalizePositiveInt(
      rawSettings.stepUpReauthMinutes,
      SESSION_SECURITY_DEFAULTS.stepUpReauthMinutes,
      { min: 5, max: 1440 }
    ),
  };
}

function buildRiskThresholds(rawSettings = {}, defaults = SECURITY_RISK_THRESHOLDS_DEFAULTS) {
  const low = normalizePositiveInt(rawSettings.low, defaults.low, { min: 5, max: 500 });
  const medium = normalizePositiveInt(rawSettings.medium, defaults.medium, { min: low + 1, max: 700 });
  const high = normalizePositiveInt(rawSettings.high, defaults.high, { min: medium + 1, max: 1000 });
  return {
    low,
    medium: Math.max(low + 1, medium),
    high: Math.max(Math.max(low + 1, medium) + 1, high),
  };
}

function resolveRiskLevel(scoreRaw, thresholds = SECURITY_RISK_THRESHOLDS_DEFAULTS) {
  const score = Number(scoreRaw || 0);
  const normalizedThresholds = buildRiskThresholds(thresholds, SECURITY_RISK_THRESHOLDS_DEFAULTS);
  if (score >= normalizedThresholds.high) return { key: 'high', label: 'High' };
  if (score >= normalizedThresholds.medium) return { key: 'medium', label: 'Medium' };
  if (score >= normalizedThresholds.low) return { key: 'low', label: 'Low' };
  return { key: 'none', label: 'None' };
}

function sortForStableJson(value) {
  if (Array.isArray(value)) {
    return value.map((item) => sortForStableJson(item));
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  return Object.keys(value)
    .sort()
    .reduce((acc, key) => {
      acc[key] = sortForStableJson(value[key]);
      return acc;
    }, {});
}

function stableStringify(value) {
  return JSON.stringify(sortForStableJson(value));
}

function computeHashChainValue(payload, previousHash = '') {
  const serialized = stableStringify(payload);
  return createHash('sha256')
    .update(`${String(previousHash || '')}|${serialized}`)
    .digest('hex');
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
    && normalizedProvidedToken === normalizedStatusAccessToken
  ) {
    return true;
  }
  if (isAdmin || isDeanery) {
    return true;
  }
  return isLoopbackIpAddress(clientIp);
}

module.exports = {
  ADMIN_IP_ALLOWLIST_LIMIT,
  ADMIN_IP_RULE_MAX_LENGTH,
  SECURITY_RISK_RULE_WEIGHTS,
  SECURITY_RISK_THRESHOLDS_DEFAULTS,
  SESSION_SECURITY_DEFAULTS,
  TRUSTED_ADMIN_IP_RISK_BONUS,
  buildDeviceFingerprint,
  buildGeoFingerprint,
  buildRiskThresholds,
  canAccessOperationalDetails,
  computeHashChainValue,
  evaluateImpossibleTravel,
  formatAdminIpAllowlist,
  isLoopbackIpAddress,
  matchAdminIpAllowlist,
  normalizeIpAddress,
  normalizeSessionSecuritySettings,
  normalizeUserAgent,
  parseAdminIpAllowlist,
  resolveDbSslConfig,
  resolveRiskLevel,
  resolveSessionSecret,
  resolveTrustProxySetting,
};
