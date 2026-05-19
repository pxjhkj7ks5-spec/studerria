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
  let telegramSessionSyncPromise = null;
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

  function syncTelegramSession() {
    if (!shouldSyncTelegramSession()) return Promise.resolve(null);
    if (telegramSessionSyncPromise) return telegramSessionSyncPromise;
    telegramSessionSyncPromise = (async () => {
    try {
      const response = await fetch('/studerria-tg/auth/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ initData: tg.initData }),
      });
      const data = await response.json().catch(() => null);
      if (!data || !data.redirect) return data;
      const currentPath = window.location.pathname || '';
      const shouldEnterApp = isEntryPath(currentPath);
      if (data.status === 'authenticated' && shouldEnterApp && currentPath !== data.redirect) {
        data.redirecting = true;
        window.location.replace(data.redirect);
        return data;
      }
      if (data.status === 'link_required') {
        const redirectUrl = new URL(data.redirect, window.location.origin);
        const currentSearch = window.location.search || '';
        if (currentPath !== redirectUrl.pathname || currentSearch !== redirectUrl.search) {
          data.redirecting = true;
          window.location.replace(data.redirect);
          return data;
        }
      }
      if (data.ok === false && data.error) {
        document.documentElement.dataset.tgAuthError = data.error;
      }
      return data;
    } catch (_error) {
      document.documentElement.dataset.tgAuthError = 'network';
      return null;
    } finally {
      telegramSessionSyncPromise = null;
    }
    })();
    return telegramSessionSyncPromise;
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
    bindRegisterForms();
    bindSubjectPickers();
    bindScheduleHomeworkModal();
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

  function fillTelegramInitData(form) {
    const initDataInput = form.querySelector('[data-tg-init-data]');
    if (initDataInput && tg && tg.initData) initDataInput.value = tg.initData;
  }

  function bindRegisterForms() {
    document.querySelectorAll('[data-tg-register-form]').forEach((form) => {
      if (form.dataset.tgRegisterBound === '1') return;
      form.dataset.tgRegisterBound = '1';
      form.addEventListener('submit', async (event) => {
        fillTelegramInitData(form);
        if (!shouldSyncTelegramSession() || form.dataset.tgRegisterSynced === '1') return;
        event.preventDefault();
        const submitter = event.submitter || form.querySelector('button[type="submit"]');
        if (submitter) submitter.disabled = true;
        const syncResult = await syncTelegramSession();
        if (syncResult && syncResult.redirecting) return;
        fillTelegramInitData(form);
        form.dataset.tgRegisterSynced = '1';
        if (submitter) submitter.disabled = false;
        if (typeof form.requestSubmit === 'function') {
          form.requestSubmit(submitter || undefined);
        } else {
          form.submit();
        }
      });
    });
  }

  function isSubjectCardReady(card) {
    if (!card) return false;
    if (card.querySelector('input[type="hidden"][name^="subject_"]')) return true;
    if (card.querySelector('input[type="radio"][name^="subject_"]:checked')) return true;
    if (card.querySelector('input[type="checkbox"][name^="optout_"]:checked')) return true;
    return false;
  }

  function updateSubjectPickerState(form) {
    const cards = Array.from(form.querySelectorAll('[data-tg-subject-card]'));
    const total = cards.length;
    const readyCount = cards.filter((card) => {
      const ready = isSubjectCardReady(card);
      card.classList.toggle('is-ready', ready);
      card.classList.toggle('is-pending', !ready);
      const status = card.querySelector('[data-tg-subject-status]');
      if (status) {
        status.classList.toggle('is-ready', ready);
        status.classList.toggle('is-pending', !ready);
        status.textContent = ready ? 'Готово' : 'Обрати';
      }
      return ready;
    }).length;
    const count = document.querySelector('[data-tg-subject-count]');
    if (count && total) count.textContent = `${readyCount}/${total}`;
    const progress = document.querySelector('[data-tg-subject-progress] span');
    if (progress && total) progress.style.width = `${Math.round((readyCount / total) * 100)}%`;
    const remaining = document.querySelector('[data-tg-subject-remaining]');
    if (remaining && total) {
      const missing = Math.max(0, total - readyCount);
      remaining.textContent = missing ? `Залишилось обрати: ${missing}` : 'Усе готово.';
    }
  }

  function bindSubjectPickers() {
    document.querySelectorAll('[data-tg-subject-picker]').forEach((form) => {
      if (form.dataset.tgSubjectPickerBound === '1') return;
      form.dataset.tgSubjectPickerBound = '1';
      form.addEventListener('change', (event) => {
        if (!event.target || !event.target.matches('input[type="radio"], input[type="checkbox"]')) return;
        updateSubjectPickerState(form);
      });
      updateSubjectPickerState(form);
    });
  }

  function bindScheduleHomeworkModal() {
    const modal = document.getElementById('tgHomeworkModal');
    if (!modal || modal.dataset.tgHomeworkModalBound === '1') return;
    modal.dataset.tgHomeworkModalBound = '1';
    const form = modal.querySelector('form');
    const meta = modal.querySelector('[data-tg-homework-meta]');
    const fields = {
      subject_id: modal.querySelector('[data-tg-homework-field="subject_id"]'),
      course_id: modal.querySelector('[data-tg-homework-field="course_id"]'),
      group_number: modal.querySelector('[data-tg-homework-field="group_number"]'),
      day_of_week: modal.querySelector('[data-tg-homework-field="day_of_week"]'),
      class_number: modal.querySelector('[data-tg-homework-field="class_number"]'),
      class_date: modal.querySelector('[data-tg-homework-field="class_date"]'),
      time: modal.querySelector('[data-tg-homework-field="time"]'),
    };
    function lockPageScroll() {
      const scrollY = window.scrollY || document.documentElement.scrollTop || 0;
      modal.dataset.scrollY = String(scrollY);
      document.body.style.top = `-${scrollY}px`;
      document.documentElement.classList.add('is-tg-modal-open');
      document.body.classList.add('is-tg-modal-open');
    }
    function unlockPageScroll() {
      const scrollY = Number(modal.dataset.scrollY || 0);
      document.documentElement.classList.remove('is-tg-modal-open');
      document.body.classList.remove('is-tg-modal-open');
      document.body.style.top = '';
      delete modal.dataset.scrollY;
      if (typeof window.scrollTo === 'function') {
        window.scrollTo(0, scrollY);
      } else {
        document.documentElement.scrollTop = scrollY;
        document.body.scrollTop = scrollY;
      }
    }
    function closeModal() {
      if (modal.hidden) return;
      modal.hidden = true;
      unlockPageScroll();
    }
    function openModal(button) {
      if (!button) return;
      if (fields.subject_id) fields.subject_id.value = button.dataset.subjectId || '';
      if (fields.course_id) fields.course_id.value = button.dataset.courseId || '';
      if (fields.group_number) fields.group_number.value = button.dataset.groupNumber || '';
      if (fields.day_of_week) fields.day_of_week.value = button.dataset.dayOfWeek || '';
      if (fields.class_number) fields.class_number.value = button.dataset.classNumber || '';
      if (fields.class_date) fields.class_date.value = button.dataset.classDate || '';
      if (fields.time) fields.time.value = button.dataset.time || '';
      if (meta) {
        const date = button.dataset.classDate || '';
        const group = button.dataset.groupNumber ? ` · група ${button.dataset.groupNumber}` : '';
        const classLabel = button.dataset.classNumber ? ` · ${button.dataset.classNumber} пара` : '';
        meta.textContent = `${button.dataset.subjectName || 'Пара'}${classLabel}${group}${date ? ` · ${date}` : ''}`;
      }
      if (form) {
        form.reset();
        Object.keys(fields).forEach((key) => {
          if (!fields[key]) return;
          const dataKey = key.replace(/_([a-z])/g, (_match, letter) => letter.toUpperCase());
          fields[key].value = button.dataset[dataKey] || fields[key].value || '';
        });
        const submit = form.querySelector('button[type="submit"]');
        if (submit) submit.disabled = false;
      }
      modal.hidden = false;
      lockPageScroll();
      const textarea = modal.querySelector('textarea[name="description"]');
      if (textarea) window.setTimeout(() => textarea.focus(), 80);
    }
    document.querySelectorAll('[data-tg-homework-open]').forEach((button) => {
      if (button.dataset.tgHomeworkBound === '1') return;
      button.dataset.tgHomeworkBound = '1';
      button.addEventListener('click', () => openModal(button));
    });
    modal.querySelectorAll('[data-tg-homework-close]').forEach((button) => {
      button.addEventListener('click', closeModal);
    });
    modal.addEventListener('click', (event) => {
      if (event.target === modal) closeModal();
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && !modal.hidden) closeModal();
    });
    if (form) {
      form.addEventListener('submit', () => {
        const submit = form.querySelector('button[type="submit"]');
        if (submit) submit.disabled = true;
      });
    }
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
  bindRegisterForms();
  bindSubjectPickers();
  bindScheduleHomeworkModal();
  primeFastPages();
  syncTelegramSession();
})();
