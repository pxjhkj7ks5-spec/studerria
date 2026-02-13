(() => {
  const THEME_ATTR = 'data-theme';
  const THEME_VALUES = new Set(['dark', 'light']);
  let isThemeSyncing = false;

  function normalizeText(value) {
    return (value || '').replace(/\s+/g, ' ').trim();
  }

  function detectTheme() {
    const body = document.body;
    const root = document.documentElement;
    if (!body) {
      return 'dark';
    }
    if (body.classList.contains('theme-light') || root.classList.contains('theme-light')) {
      return 'light';
    }
    if (body.classList.contains('theme-dark') || root.classList.contains('theme-dark')) {
      return 'dark';
    }

    const attrTheme = (body.getAttribute(THEME_ATTR) || root.getAttribute(THEME_ATTR) || '').toLowerCase();
    if (THEME_VALUES.has(attrTheme)) {
      return attrTheme;
    }

    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function syncThemeAttribute() {
    const body = document.body;
    if (!body) {
      return;
    }
    const theme = detectTheme();
    const root = document.documentElement;
    const rootTheme = root.getAttribute(THEME_ATTR);
    const bodyTheme = body.getAttribute(THEME_ATTR);

    if (rootTheme === theme && bodyTheme === theme) {
      return;
    }

    isThemeSyncing = true;
    try {
      if (rootTheme !== theme) {
        root.setAttribute(THEME_ATTR, theme);
      }
      if (bodyTheme !== theme) {
        body.setAttribute(THEME_ATTR, theme);
      }
    } finally {
      isThemeSyncing = false;
    }
  }

  function applySemanticBadge(el) {
    if (!(el instanceof HTMLElement)) {
      return;
    }
    const text = normalizeText(el.textContent).toLowerCase();
    if (!text) {
      return;
    }

    if (/контроль/u.test(text)) {
      el.classList.add('badge--control');
      el.classList.remove('badge--hw');
      return;
    }

    if (/(^|\s)д\s*\/?\s*з\b/u.test(text)) {
      el.classList.add('badge--hw');
      el.classList.remove('badge--control');
    }
  }

  function applySemanticBadges(root) {
    const scope = root instanceof HTMLElement || root instanceof Document ? root : document;
    const nodes = scope.querySelectorAll
      ? scope.querySelectorAll('.badge, .chip, .tag-pill, .priority-chip, .hw-chip, .control-chip, [data-semantic-chip]')
      : [];

    nodes.forEach((node) => applySemanticBadge(node));
  }

  function observeThemeChanges() {
    const body = document.body;
    if (!body) {
      return;
    }

    const observer = new MutationObserver(() => {
      if (isThemeSyncing) {
        return;
      }
      syncThemeAttribute();
    });

    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class', THEME_ATTR],
    });

    observer.observe(body, {
      attributes: true,
      attributeFilter: ['class', THEME_ATTR],
    });
  }

  function observeDynamicBadges() {
    const body = document.body;
    if (!body) {
      return;
    }

    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (!(node instanceof HTMLElement)) {
            return;
          }
          applySemanticBadge(node);
          applySemanticBadges(node);
        });
      });
    });

    observer.observe(body, {
      childList: true,
      subtree: true,
    });
  }

  function init() {
    syncThemeAttribute();
    applySemanticBadges(document);
    observeThemeChanges();
    observeDynamicBadges();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
