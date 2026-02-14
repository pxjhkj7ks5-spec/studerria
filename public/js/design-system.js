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

  function getTopVisibleModal() {
    const visibleModals = document.querySelectorAll('.modal.show');
    return visibleModals.length ? visibleModals[visibleModals.length - 1] : null;
  }

  function initModalBehavior() {
    if (!window.bootstrap || !window.bootstrap.Modal) {
      return;
    }

    const modalTriggerMap = new WeakMap();

    document.addEventListener('show.bs.modal', (event) => {
      const modal = event.target;
      if (!(modal instanceof HTMLElement) || !modal.classList.contains('modal')) {
        return;
      }

      const relatedTarget = event.relatedTarget instanceof HTMLElement ? event.relatedTarget : null;
      const activeElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      const trigger = relatedTarget || activeElement;

      if (trigger && trigger !== document.body && trigger !== modal && !modal.contains(trigger)) {
        modalTriggerMap.set(modal, trigger);
      }
    });

    document.addEventListener('hidden.bs.modal', (event) => {
      const modal = event.target;
      if (!(modal instanceof HTMLElement) || !modal.classList.contains('modal')) {
        return;
      }

      const trigger = modalTriggerMap.get(modal);
      modalTriggerMap.delete(modal);

      if (trigger && trigger.isConnected && typeof trigger.focus === 'function') {
        requestAnimationFrame(() => {
          try {
            trigger.focus({ preventScroll: true });
          } catch (_error) {
            trigger.focus();
          }
        });
      }
    });

    document.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape' || event.defaultPrevented) {
        return;
      }

      const topModal = getTopVisibleModal();
      if (!(topModal instanceof HTMLElement)) {
        return;
      }

      if (topModal.getAttribute('data-bs-keyboard') === 'false') {
        return;
      }

      const instance = window.bootstrap.Modal.getInstance(topModal);
      if (instance) {
        instance.hide();
      }
    });

    document.addEventListener('mousedown', (event) => {
      const modal = event.target;
      if (!(modal instanceof HTMLElement)) {
        return;
      }

      if (!modal.classList.contains('modal') || !modal.classList.contains('show')) {
        return;
      }

      const topModal = getTopVisibleModal();
      if (modal !== topModal) {
        return;
      }

      if (modal.getAttribute('data-bs-backdrop') === 'static') {
        return;
      }

      const instance = window.bootstrap.Modal.getInstance(modal);
      if (instance) {
        instance.hide();
      }
    });
  }

  function init() {
    syncThemeAttribute();
    applySemanticBadges(document);
    observeThemeChanges();
    observeDynamicBadges();
    initModalBehavior();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
