function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.role !== 'admin') {
    return res.status(403).send('Forbidden');
  }
  return next();
}

function requireStaff(req, res, next) {
  if (!req.session.user || !['admin', 'starosta'].includes(req.session.role)) {
    return res.status(403).send('Forbidden');
  }
  return next();
}

function requireOverviewAccess(req, res, next) {
  if (!req.session.user || !['admin', 'starosta', 'deanery'].includes(req.session.role)) {
    return res.status(403).send('Forbidden');
  }
  return next();
}

function requireDeanery(req, res, next) {
  if (!req.session.user || req.session.role !== 'deanery') {
    return res.redirect('/schedule');
  }
  return next();
}

function requireAdminOrDeanery(req, res, next) {
  if (!req.session.user || !['admin', 'deanery'].includes(req.session.role)) {
    return res.status(403).send('Forbidden');
  }
  return next();
}

function requireHomeworkBulkAccess(req, res, next) {
  if (!req.session.user || !['admin', 'deanery', 'starosta'].includes(req.session.role)) {
    return res.status(403).send('Forbidden');
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
