(() => {
  if (window.__studerriaBackgroundInitialized) return;
  window.__studerriaBackgroundInitialized = true;

  const THEME_CONTROL_SELECTOR = '.theme-toggle, .studerria-theme-toggle, .theme-toggle-btn, [data-theme-toggle], [data-nav-action="theme-toggle"]';

  function normalizeTheme(rawValue) {
    const value = String(rawValue || '').trim().toLowerCase();
    if (value === 'dark' || value === 'theme-dark') return 'dark';
    if (value === 'light' || value === 'theme-light') return 'light';
    return '';
  }

  function storedTheme() {
    try {
      return normalizeTheme(localStorage.getItem('ui-theme'))
        || normalizeTheme(localStorage.getItem('studerria-test-theme'));
    } catch (_error) {
      return '';
    }
  }

  function persistTheme(theme) {
    try {
      localStorage.setItem('ui-theme', theme === 'dark' ? 'theme-dark' : 'theme-light');
      localStorage.setItem('studerria-test-theme', theme);
    } catch (_error) {
      // Theme persistence is optional when storage is unavailable.
    }
  }

  function resolveTheme() {
    const body = document.body;
    const html = document.documentElement;
    if (body?.classList.contains('theme-dark') || body?.classList.contains('dark')) return 'dark';
    if (body?.classList.contains('theme-light') || body?.classList.contains('light')) return 'light';
    return normalizeTheme(body?.getAttribute('data-theme'))
      || normalizeTheme(html.getAttribute('data-theme'))
      || storedTheme()
      || 'light';
  }

  function syncThemeControls(theme) {
    const isDark = theme === 'dark';
    document.querySelectorAll(THEME_CONTROL_SELECTOR).forEach((control) => {
      if (!(control instanceof HTMLElement)) return;
      control.setAttribute('aria-pressed', String(isDark));
      control.setAttribute('aria-label', isDark ? 'Увімкнути світлу тему' : 'Увімкнути темну тему');
      control.querySelectorAll('[data-theme-label]').forEach((label) => {
        label.textContent = isDark ? 'Світла' : 'Темна';
      });
      const nextText = isDark
        ? control.getAttribute('data-light-label')
        : control.getAttribute('data-dark-label');
      if (nextText && !control.querySelector('[data-theme-label], .snav-label')) {
        control.textContent = nextText;
      }
      if (control.dataset.navAction === 'theme-toggle' && control.dataset.staticLabel !== 'true') {
        const label = control.querySelector('.snav-label');
        if (label && nextText) label.textContent = nextText;
      }
    });
  }

  function applyTheme(theme, persist = false) {
    const next = theme === 'dark' ? 'dark' : 'light';
    const body = document.body;
    document.documentElement.setAttribute('data-theme', next);
    if (body) {
      body.setAttribute('data-theme', next);
      body.classList.remove('theme-light', 'theme-dark', 'light', 'dark');
      body.classList.add(next === 'dark' ? 'theme-dark' : 'theme-light');
    }
    if (persist) persistTheme(next);
    syncThemeControls(next);
  }

  document.addEventListener('DOMContentLoaded', () => {
    applyTheme(resolveTheme());
    document.addEventListener('click', (event) => {
      if (event.defaultPrevented) return;
      const control = event.target instanceof Element
        ? event.target.closest(THEME_CONTROL_SELECTOR)
        : null;
      if (!(control instanceof HTMLElement)) return;
      event.preventDefault();
      applyTheme(resolveTheme() === 'dark' ? 'light' : 'dark', true);
    });
  });
})();
