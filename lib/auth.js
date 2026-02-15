function normalizeRole(rawRole) {
  return String(rawRole || '').trim().toLowerCase();
}

function getSessionRoles(req) {
  if (!req || !req.session) return [];
  const roles = Array.isArray(req.session.roles) ? req.session.roles : [];
  const normalized = roles.map(normalizeRole).filter(Boolean);
  if (normalized.length) return Array.from(new Set(normalized));
  if (req.session.role) return [normalizeRole(req.session.role)];
  return [];
}

function hasAnyRole(req, roleList) {
  const userRoles = getSessionRoles(req);
  if (!userRoles.length) return false;
  const wanted = new Set((roleList || []).map(normalizeRole));
  return userRoles.some((role) => wanted.has(role));
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || !hasAnyRole(req, ['admin'])) {
    return res.status(403).send('Forbidden (update page)');
  }
  return next();
}

function requireStaff(req, res, next) {
  if (!req.session.user || !hasAnyRole(req, ['admin', 'starosta'])) {
    return res.status(403).send('Forbidden (update page)');
  }
  return next();
}

function requireOverviewAccess(req, res, next) {
  if (!req.session.user || !hasAnyRole(req, ['admin', 'starosta', 'deanery'])) {
    return res.status(403).send('Forbidden (update page)');
  }
  return next();
}

function requireDeanery(req, res, next) {
  if (!req.session.user || !hasAnyRole(req, ['deanery'])) {
    return res.redirect('/schedule');
  }
  return next();
}

function requireAdminOrDeanery(req, res, next) {
  if (!req.session.user || !hasAnyRole(req, ['admin', 'deanery'])) {
    return res.status(403).send('Forbidden (update page)');
  }
  return next();
}

function requireHomeworkBulkAccess(req, res, next) {
  if (!req.session.user || !hasAnyRole(req, ['admin', 'deanery', 'starosta'])) {
    return res.status(403).send('Forbidden (update page)');
  }
  return next();
}

module.exports = {
  requireLogin,
  requireAdmin,
  requireStaff,
  requireOverviewAccess,
  requireDeanery,
  requireAdminOrDeanery,
  requireHomeworkBulkAccess,
};
