const { navConfig } = require('../config/nav.config');

function normalizePath(value) {
  const raw = String(value || '').trim();
  if (!raw) return '/';
  const withoutQuery = raw.split('#')[0].split('?')[0].trim();
  if (!withoutQuery || withoutQuery === '/') return '/';
  return withoutQuery.replace(/\/+$/, '') || '/';
}

function getHrefPath(href) {
  if (!href) return '';
  return normalizePath(href);
}

function hasAllowedRole(item, userNav) {
  if (!Array.isArray(item.rolesAllowed) || !item.rolesAllowed.length) {
    return true;
  }
  const roles = Array.isArray(userNav.roles) ? userNav.roles : [];
  return item.rolesAllowed.some((role) => roles.includes(role));
}

function hasRequiredFlags(item, userNav) {
  if (!Array.isArray(item.requiredFlags) || !item.requiredFlags.length) {
    return true;
  }
  const flags = userNav.flags || {};
  return item.requiredFlags.every((flagName) => Boolean(flags[flagName]));
}

function isItemAllowed(item, userNav) {
  return hasAllowedRole(item, userNav) && hasRequiredFlags(item, userNav);
}

function isItemActive(item, currentPath) {
  const path = normalizePath(currentPath);
  const matchPaths = Array.isArray(item.matchPaths) && item.matchPaths.length
    ? item.matchPaths
    : [item.href];
  const normalizedMatches = matchPaths
    .map((entry) => getHrefPath(entry))
    .filter(Boolean);

  if (!normalizedMatches.length) {
    return false;
  }

  if (item.matchMode === 'prefix') {
    return normalizedMatches.some((entry) => path === entry || path.startsWith(`${entry}/`));
  }

  return normalizedMatches.includes(path);
}

function cloneNavItem(item, overrides = {}) {
  return {
    ...item,
    ...overrides,
    children: Array.isArray(overrides.children)
      ? overrides.children
      : (Array.isArray(item.children) ? item.children.map((child) => cloneNavItem(child)) : []),
  };
}

function canUseCustomDeadlines(userNav, settings) {
  if (!settings || !settings.allow_custom_deadlines) {
    return false;
  }
  const roles = Array.isArray(userNav && userNav.roles) ? userNav.roles : [];
  if (roles.some((role) => ['admin', 'deanery', 'teacher'].includes(role))) {
    return true;
  }
  return Boolean(settings && settings.allow_homework_creation);
}

function filterNavItems(items, context) {
  return items.reduce((result, item) => {
    if (!isItemAllowed(item, context.userNav) || item.hidden) {
      return result;
    }

    const filteredChildren = Array.isArray(item.children)
      ? filterNavItems(item.children, context)
      : [];
    const active = isItemActive(item, context.currentPath);
    const nextItem = cloneNavItem(item, { children: filteredChildren });
    nextItem.isCurrent = active;

    if (active && filteredChildren.length && item.keepWhenActive) {
      nextItem.href = '';
      nextItem.isCurrentContainer = true;
      nextItem.isDisabledLink = true;
      result.push(nextItem);
      return result;
    }

    if (active) {
      result.push(nextItem);
      return result;
    }

    if (Array.isArray(item.children) && item.children.length && !filteredChildren.length && !item.href) {
      return result;
    }

    result.push(nextItem);
    return result;
  }, []);
}

function buildUserNav(req, res) {
  const session = req && req.session ? req.session : {};
  const sessionUser = session && session.user ? session.user : null;
  const role = sessionUser ? (String(session.role || '').trim() || 'student') : '';
  const roles = sessionUser
    ? (Array.isArray(session.roles) && session.roles.length ? session.roles : [role])
    : [];
  const settings = res && res.locals ? res.locals.settings : {};

  return {
    isAuthenticated: Boolean(sessionUser),
    role,
    roles,
    name: sessionUser && sessionUser.username ? String(sessionUser.username).trim() : '',
    flags: {
      canAccessAdminPanel: Boolean(req && req.canAccessAdminPanel),
      canManagePathways: Boolean(req && req.canManagePathways),
      allowMessages: Boolean(settings && settings.allow_messages),
      allowCustomDeadlines: Boolean(settings && settings.allow_custom_deadlines),
      canUseCustomDeadlines: canUseCustomDeadlines({ roles }, settings),
    },
    personalLabel: navConfig.personalLabel,
  };
}

module.exports = function navMiddleware(req, res, next) {
  const currentPath = normalizePath(req.path);
  const userNav = buildUserNav(req, res);
  const configItems = Array.isArray(navConfig.items) ? navConfig.items.map((item) => cloneNavItem(item)) : [];
  const visibleItems = userNav.isAuthenticated
    ? filterNavItems(configItems, { currentPath, userNav })
    : [];

  res.locals.role = userNav.role;
  res.locals.username = userNav.name;
  res.locals.currentPath = currentPath;
  res.locals.userNav = userNav;
  res.locals.navItems = visibleItems;
  res.locals.navMeta = {
    personalLabel: userNav.personalLabel,
  };

  next();
};
