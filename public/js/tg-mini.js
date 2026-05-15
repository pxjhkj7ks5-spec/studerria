(function initStuderriaTelegramMini() {
  const tg = window.Telegram && window.Telegram.WebApp ? window.Telegram.WebApp : null;
  const state = window.__studerriaTg || {};
  const fastRoutePaths = new Set([
    '/studerria-tg/schedule',
    '/studerria-tg/teamwork',
    '/studerria-tg/profile',
    '/studerria-tg/subjects',
  ]);
  const pageCache = new Map();
  let activeNavigationRequest = null;
  const systemDarkQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  function colorIsDark(rawColor) {
    const hex = String(rawColor || '').trim().replace('#', '');
    if (!/^[0-9a-f]{6}$/i.test(hex)) return false;
    const red = parseInt(hex.slice(0, 2), 16);
    const green = parseInt(hex.slice(2, 4), 16);
    const blue = parseInt(hex.slice(4, 6), 16);
    return ((red * 299 + green * 587 + blue * 114) / 1000) < 145;
  }

  function getPreferredDarkMode() {
    if (tg && typeof tg.colorScheme === 'string' && tg.colorScheme) {
      return tg.colorScheme === 'dark';
    }
    const bg = tg && tg.themeParams && tg.themeParams.bg_color;
    if (bg) return colorIsDark(bg);
    return Boolean(systemDarkQuery && systemDarkQuery.matches);
  }

  function applyThemeMode() {
    const isDark = getPreferredDarkMode();
    document.documentElement.classList.toggle('is-tg-dark', isDark);
    const themeMeta = document.querySelector('meta[name="theme-color"]');
    if (themeMeta) themeMeta.setAttribute('content', isDark ? '#111214' : '#f6f4f0');
  }

  function applyTelegramChrome() {
    try {
      if (tg) {
        tg.ready();
        tg.expand();
        document.documentElement.style.setProperty('--tg-viewport-height', `${tg.viewportStableHeight || tg.viewportHeight || window.innerHeight}px`);
        const button = tg.themeParams && tg.themeParams.button_color;
        if (button && /^#[0-9a-f]{6}$/i.test(button)) {
          document.documentElement.style.setProperty('--tg-theme-accent', button);
        }
      } else {
        document.documentElement.style.setProperty('--tg-viewport-height', `${window.innerHeight}px`);
      }
      applyThemeMode();
    } catch (_error) {}
  }

  function isEntryPath(pathname) {
    return pathname === '/studerria-tg'
      || pathname === '/studerria-tg/login'
      || pathname === '/studerria-tg/register';
  }

  function shouldSyncTelegramSession() {
    if (!tg || !tg.initData) return false;
    if (!state.authenticated) return true;
    return isEntryPath(window.location.pathname || state.currentPath || '');
  }

  async function syncTelegramSession() {
    if (!shouldSyncTelegramSession()) return;
    try {
      const response = await fetch('/studerria-tg/auth/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ initData: tg.initData }),
      });
      const data = await response.json().catch(() => null);
      if (!data || !data.redirect) return;
      const currentPath = window.location.pathname || '';
      const shouldEnterApp = isEntryPath(currentPath);
      if (data.status === 'authenticated' && shouldEnterApp && currentPath !== data.redirect) {
        window.location.replace(data.redirect);
        return;
      }
      if (data.status === 'link_required') {
        const redirectUrl = new URL(data.redirect, window.location.origin);
        const currentSearch = window.location.search || '';
        if (currentPath !== redirectUrl.pathname || currentSearch !== redirectUrl.search) {
          window.location.replace(data.redirect);
          return;
        }
        if (currentPath === '/studerria-tg/register' && !sessionStorage.getItem('studerriaTgRegisterSynced')) {
          sessionStorage.setItem('studerriaTgRegisterSynced', '1');
          window.location.reload();
        }
      }
      if (data.ok === false && data.error) {
        document.documentElement.dataset.tgAuthError = data.error;
      }
    } catch (_error) {
      document.documentElement.dataset.tgAuthError = 'network';
    }
  }

  function getFastUrl(href) {
    if (!href) return null;
    try {
      const url = new URL(href, window.location.origin);
      if (url.origin !== window.location.origin) return null;
      if (!fastRoutePaths.has(url.pathname)) return null;
      return url;
    } catch (_error) {
      return null;
    }
  }

  function parsePage(html, responseUrl) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const shell = doc.querySelector('.tg-shell');
    if (!shell) return null;
    return {
      url: responseUrl || window.location.href,
      title: doc.title || document.title,
      shellHtml: shell.innerHTML,
      navHtml: doc.querySelector('.tg-bottom-nav') ? doc.querySelector('.tg-bottom-nav').outerHTML : '',
      bodyClass: doc.body ? doc.body.className : document.body.className,
      currentPage: doc.body ? doc.body.getAttribute('data-current-page') || '' : '',
    };
  }

  async function fetchFastPage(url) {
    const cacheKey = url.pathname + url.search;
    if (pageCache.has(cacheKey)) return pageCache.get(cacheKey);
    const response = await fetch(url.toString(), {
      method: 'GET',
      credentials: 'same-origin',
      headers: { 'X-Requested-With': 'StuderriaTelegramMini' },
    });
    if (!response.ok) throw new Error('page_load_failed');
    const finalUrl = new URL(response.url || url.toString(), window.location.origin);
    if (finalUrl.origin !== window.location.origin || !fastRoutePaths.has(finalUrl.pathname)) {
      throw new Error('page_redirected');
    }
    const page = parsePage(await response.text(), response.url);
    if (!page) throw new Error('page_parse_failed');
    pageCache.set(cacheKey, page);
    return page;
  }

  function applyFastPage(page, pushUrl) {
    const shell = document.querySelector('.tg-shell');
    if (!shell) {
      window.location.href = pushUrl.toString();
      return;
    }
    shell.innerHTML = page.shellHtml;
    const currentNav = document.querySelector('.tg-bottom-nav');
    if (page.navHtml) {
      if (currentNav) {
        currentNav.outerHTML = page.navHtml;
      } else {
        document.body.insertAdjacentHTML('beforeend', page.navHtml);
      }
    } else if (currentNav) {
      currentNav.remove();
    }
    document.title = page.title;
    document.body.className = page.bodyClass;
    document.body.setAttribute('data-current-page', page.currentPage);
    state.currentPath = pushUrl.pathname;
    state.authenticated = true;
    window.scrollTo(0, 0);
    bindFastNavigation();
    bindTelegramLinkForms();
    primeFastPages();
    applyTelegramChrome();
  }

  async function navigateFast(url, options) {
    const targetUrl = url instanceof URL ? url : getFastUrl(url);
    if (!targetUrl) return false;
    const cacheKey = targetUrl.pathname + targetUrl.search;
    const requestId = `${Date.now()}:${cacheKey}`;
    activeNavigationRequest = requestId;
    document.documentElement.classList.add('is-tg-navigating');
    try {
      const page = await fetchFastPage(targetUrl);
      if (activeNavigationRequest !== requestId) return true;
      applyFastPage(page, targetUrl);
      if (!options || options.push !== false) {
        window.history.pushState({ studerriaTg: true }, page.title, targetUrl.toString());
      }
      return true;
    } catch (_error) {
      window.location.href = targetUrl.toString();
      return true;
    } finally {
      if (activeNavigationRequest === requestId) activeNavigationRequest = null;
      document.documentElement.classList.remove('is-tg-navigating');
    }
  }

  function bindFastNavigation() {
    document.querySelectorAll('a[href]').forEach((anchor) => {
      if (anchor.dataset.tgFastBound === '1') return;
      const url = getFastUrl(anchor.getAttribute('href'));
      if (!url) return;
      anchor.dataset.tgFastBound = '1';
      anchor.addEventListener('click', (event) => {
        if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        if (anchor.target || anchor.hasAttribute('download')) return;
        event.preventDefault();
        navigateFast(url);
      });
    });
  }

  function bindTelegramLinkForms() {
    document.querySelectorAll('[data-tg-link-form]').forEach((form) => {
      if (form.dataset.tgLinkBound === '1') return;
      form.dataset.tgLinkBound = '1';
      form.addEventListener('submit', (event) => {
        const initDataInput = form.querySelector('[data-tg-init-data]');
        const status = form.querySelector('[data-tg-link-status]');
        const initData = tg && tg.initData ? tg.initData : '';
        if (initDataInput) initDataInput.value = initData;
        if (initData) return;
        event.preventDefault();
        if (status) {
          status.hidden = false;
          status.textContent = 'Telegram не передав дані для привʼязки. Закрийте mini app і відкрийте його з Telegram ще раз.';
        }
      });
    });
  }

  function primeFastPages() {
    const urls = new Map();
    document.querySelectorAll('a[href]').forEach((anchor) => {
      const url = getFastUrl(anchor.getAttribute('href'));
      if (url) urls.set(url.pathname + url.search, url);
    });
    fastRoutePaths.forEach((pathname) => {
      urls.set(pathname, new URL(pathname, window.location.origin));
    });
    urls.forEach((url, key) => {
      if (key === `${window.location.pathname}${window.location.search}` || pageCache.has(key)) return;
      window.setTimeout(() => {
        fetchFastPage(url).catch(() => {});
      }, 120);
    });
  }

  window.addEventListener('resize', applyTelegramChrome);
  if (systemDarkQuery) {
    const onSystemThemeChange = () => applyTelegramChrome();
    if (systemDarkQuery.addEventListener) {
      systemDarkQuery.addEventListener('change', onSystemThemeChange);
    } else if (systemDarkQuery.addListener) {
      systemDarkQuery.addListener(onSystemThemeChange);
    }
  }
  if (tg && tg.onEvent) {
    tg.onEvent('themeChanged', applyTelegramChrome);
    tg.onEvent('viewportChanged', applyTelegramChrome);
  }
  window.addEventListener('popstate', () => {
    const url = getFastUrl(window.location.href);
    if (!url) {
      window.location.reload();
      return;
    }
    navigateFast(url, { push: false });
  });
  applyTelegramChrome();
  bindFastNavigation();
  bindTelegramLinkForms();
  primeFastPages();
  syncTelegramSession();
})();
