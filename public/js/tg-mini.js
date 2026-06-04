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
  const maxTgHomeworkFiles = 8;
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
        const isRegisterHandshake = currentPath === '/studerria-tg/register'
          && redirectUrl.pathname === '/studerria-tg/register'
          && !data.setup_status;
        if (!isRegisterHandshake && (currentPath !== redirectUrl.pathname || currentSearch !== redirectUrl.search)) {
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
    bindFileInputs();
    bindScheduleHomeworkModal();
    bindScheduleHomeworkViewModal();
    bindScheduleFilePreviewModal();
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

  function setRegisterSubmitPending(form, submitter, pending) {
    const button = submitter || (form ? form.querySelector('button[type="submit"]') : null);
    if (!button) return;
    if (!button.dataset.tgIdleLabel) {
      button.dataset.tgIdleLabel = button.textContent || '';
    }
    button.disabled = Boolean(pending);
    button.classList.toggle('is-loading', Boolean(pending));
    button.setAttribute('aria-busy', pending ? 'true' : 'false');
    button.textContent = pending ? 'Завантаження' : button.dataset.tgIdleLabel;
  }

  function bindRegisterForms() {
    document.querySelectorAll('[data-tg-register-form]').forEach((form) => {
      if (form.dataset.tgRegisterBound === '1') return;
      form.dataset.tgRegisterBound = '1';
      form.addEventListener('submit', async (event) => {
        const submitter = event.submitter || form.querySelector('button[type="submit"]');
        if (form.dataset.tgRegisterSubmitting === '1') {
          event.preventDefault();
          return;
        }
        fillTelegramInitData(form);
        setRegisterSubmitPending(form, submitter, true);
        if (!shouldSyncTelegramSession() || form.dataset.tgRegisterSynced === '1') {
          form.dataset.tgRegisterSubmitting = '1';
          return;
        }
        event.preventDefault();
        const syncResult = await syncTelegramSession();
        if (syncResult && syncResult.redirecting) return;
        fillTelegramInitData(form);
        form.dataset.tgRegisterSynced = '1';
        form.dataset.tgRegisterSubmitting = '1';
        if (typeof form.submit === 'function') {
          form.submit();
        } else if (typeof form.requestSubmit === 'function') {
          form.requestSubmit();
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

  function getTgFileLabel(element) {
    return element ? element.closest('[data-tg-file-label], .tg-file-label') : null;
  }

  function getTgFileInputs(label) {
    return label ? Array.from(label.querySelectorAll('[data-tg-file-input]')) : [];
  }

  function getTgSelectedFiles(label) {
    return getTgFileInputs(label).flatMap((input) => (
      input.files ? Array.from(input.files).filter(Boolean) : []
    ));
  }

  function formatTgFileCount(count) {
    if (count === 1) return '1 файл';
    if (count >= 5) return `${count} файлів`;
    return `${count} файли`;
  }

  function renderTgFileList(label, files) {
    const list = label ? label.querySelector('[data-tg-file-list]') : null;
    if (!list) return;
    list.innerHTML = '';
    list.hidden = !files.length;
    files.forEach((file) => {
      const chip = document.createElement('span');
      chip.className = 'tg-file-chip';
      chip.textContent = file && file.name ? file.name : 'Файл';
      list.appendChild(chip);
    });
  }

  function updateFileInputLabel(inputOrLabel) {
    if (!inputOrLabel) return;
    const label = inputOrLabel.matches && inputOrLabel.matches('[data-tg-file-label], .tg-file-label')
      ? inputOrLabel
      : getTgFileLabel(inputOrLabel);
    const name = label ? label.querySelector('[data-tg-file-name]') : null;
    if (!name) return;
    const files = getTgSelectedFiles(label);
    const addMore = label ? label.querySelector('[data-tg-file-add-more]') : null;
    getTgFileInputs(label).forEach((input) => {
      input.classList.toggle('is-filled', Boolean(input.files && input.files.length));
    });
    renderTgFileList(label, files);
    if (addMore) addMore.hidden = !files.length || files.length >= maxTgHomeworkFiles;
    if (!files.length) {
      name.textContent = 'Файли не вибрано';
      return;
    }
    if (files.length === 1) {
      name.textContent = files[0] && files[0].name ? files[0].name : '1 файл';
      return;
    }
    const firstNames = files
      .slice(0, 2)
      .map((file) => file && file.name)
      .filter(Boolean);
    const extraCount = files.length - firstNames.length;
    name.textContent = `${formatTgFileCount(files.length)}: ${firstNames.join(', ')}${extraCount > 0 ? ` +${extraCount}` : ''}`;
  }

  function bindSingleFileInput(input) {
    if (!input || input.dataset.tgFileInputBound === '1') return;
    input.dataset.tgFileInputBound = '1';
    input.addEventListener('change', () => {
      const label = getTgFileLabel(input);
      const files = getTgSelectedFiles(label);
      if (files.length > maxTgHomeworkFiles) {
        input.value = '';
        updateFileInputLabel(label);
        window.alert(`Можна додати до ${maxTgHomeworkFiles} файлів.`);
        return;
      }
      updateFileInputLabel(label);
    });
    updateFileInputLabel(input);
  }

  function createTgExtraFileInput(label) {
    if (!label) return null;
    const input = document.createElement('input');
    input.className = 'tg-file-input tg-file-input--extra';
    input.name = 'attachment';
    input.type = 'file';
    input.multiple = true;
    input.setAttribute('data-tg-file-input', '');
    label.appendChild(input);
    bindSingleFileInput(input);
    return input;
  }

  function bindFileInputs() {
    document.querySelectorAll('[data-tg-file-input]').forEach((input) => {
      if (input.dataset.tgFileInputBound === '1') {
        updateFileInputLabel(input);
        return;
      }
      bindSingleFileInput(input);
    });
    document.querySelectorAll('[data-tg-file-add-more]').forEach((button) => {
      if (button.dataset.tgFileAddMoreBound === '1') return;
      button.dataset.tgFileAddMoreBound = '1';
      button.addEventListener('click', () => {
        const label = getTgFileLabel(button);
        if (getTgSelectedFiles(label).length >= maxTgHomeworkFiles) return;
        const input = createTgExtraFileInput(label);
        if (input) input.click();
      });
    });
  }

  function getCurrentScrollY() {
    return window.scrollY || document.documentElement.scrollTop || document.body.scrollTop || 0;
  }

  function restoreScrollY(scrollY) {
    if (typeof window.scrollTo === 'function') {
      window.scrollTo(0, scrollY);
    } else {
      document.documentElement.scrollTop = scrollY;
      document.body.scrollTop = scrollY;
    }
  }

  function hasOpenTgModal(exceptModal = null) {
    return Array.from(document.querySelectorAll('.tg-modal')).some((modal) => (
      modal !== exceptModal && !modal.hidden
    ));
  }

  function lockPageScroll(modal) {
    const alreadyLocked = document.body.classList.contains('is-tg-modal-open');
    const scrollY = alreadyLocked
      ? Number(document.documentElement.dataset.tgLockedScrollY || 0)
      : getCurrentScrollY();
    if (modal) modal.dataset.scrollY = String(scrollY);
    if (!alreadyLocked) {
      document.documentElement.dataset.tgLockedScrollY = String(scrollY);
      document.body.style.top = `-${scrollY}px`;
      document.documentElement.classList.add('is-tg-modal-open');
      document.body.classList.add('is-tg-modal-open');
    }
  }

  function unlockPageScroll(modal) {
    const scrollY = Number((modal && modal.dataset.scrollY) || document.documentElement.dataset.tgLockedScrollY || 0);
    document.documentElement.classList.remove('is-tg-modal-open');
    document.body.classList.remove('is-tg-modal-open');
    document.body.style.top = '';
    delete document.documentElement.dataset.tgLockedScrollY;
    if (modal) delete modal.dataset.scrollY;
    restoreScrollY(scrollY);
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
    function closeModal() {
      if (modal.hidden) return;
      modal.hidden = true;
      unlockPageScroll(modal);
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
        form.querySelectorAll('[data-tg-file-input].tg-file-input--extra').forEach((input) => input.remove());
        form.querySelectorAll('[data-tg-file-input]').forEach((input) => updateFileInputLabel(input));
        Object.keys(fields).forEach((key) => {
          if (!fields[key]) return;
          const dataKey = key.replace(/_([a-z])/g, (_match, letter) => letter.toUpperCase());
          fields[key].value = button.dataset[dataKey] || fields[key].value || '';
        });
        const submit = form.querySelector('button[type="submit"]');
        if (submit) submit.disabled = false;
      }
      modal.hidden = false;
      lockPageScroll(modal);
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

  function formatHomeworkDate(rawValue) {
    const raw = String(rawValue || '').trim();
    const parts = raw.slice(0, 10).split('-');
    if (parts.length === 3 && parts[0] && parts[1] && parts[2]) {
      return `${parts[2]}.${parts[1]}.${parts[0]}`;
    }
    if (!raw) return '';
    const date = new Date(raw);
    return Number.isNaN(date.getTime()) ? raw : date.toLocaleDateString('uk-UA');
  }

  function resolveHomeworkHref(rawHref, { uploadsOnly = false } = {}) {
    const value = String(rawHref || '').trim();
    if (!value) return '';
    try {
      const url = new URL(value, window.location.origin);
      if (!['http:', 'https:'].includes(url.protocol)) return '';
      const sameOrigin = url.origin === window.location.origin;
      if (uploadsOnly && (!sameOrigin || !url.pathname.startsWith('/uploads/'))) return '';
      return sameOrigin ? `${url.pathname}${url.search}${url.hash}` : url.href;
    } catch (_error) {
      return '';
    }
  }

  function buildHomeworkUrl(rawHref, params = {}) {
    const safeHref = resolveHomeworkHref(rawHref, { uploadsOnly: true });
    if (!safeHref) return '';
    const url = new URL(safeHref, window.location.origin);
    Object.keys(params).forEach((key) => {
      if (params[key] !== null && typeof params[key] !== 'undefined') {
        url.searchParams.set(key, params[key]);
      }
    });
    return `${url.pathname}${url.search}${url.hash}`;
  }

  function appendHomeworkLink(container, { href, label, uploadsOnly = false } = {}) {
    const safeHref = resolveHomeworkHref(href, { uploadsOnly });
    if (!safeHref || !label) return;
    const link = document.createElement('a');
    link.className = 'tg-homework-link';
    link.href = safeHref;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = label;
    container.appendChild(link);
  }

  function appendHomeworkFileButton(container, { href, label } = {}) {
    const safeHref = resolveHomeworkHref(href, { uploadsOnly: true });
    if (!safeHref || !label) return;
    const button = document.createElement('button');
    button.className = 'tg-homework-link';
    button.type = 'button';
    button.dataset.tgFilePreviewOpen = '1';
    button.dataset.tgFileHref = safeHref;
    button.dataset.tgFileLabel = label;
    button.textContent = label;
    container.appendChild(button);
  }

  function renderHomeworkViewItem(item) {
    const card = document.createElement('article');
    card.className = 'tg-homework-card';

    const title = document.createElement('h3');
    title.textContent = item.subject_name || 'ДЗ';
    card.appendChild(title);

    const description = document.createElement('p');
    description.textContent = item.description || 'ДЗ без опису';
    card.appendChild(description);

    const metaParts = [];
    if (item.created_by) metaParts.push(`Додав: ${item.created_by}`);
    const dateLabel = formatHomeworkDate(item.class_date);
    if (dateLabel) metaParts.push(dateLabel);
    if (item.created_at) {
      const createdAt = new Date(item.created_at);
      if (!Number.isNaN(createdAt.getTime())) metaParts.push(createdAt.toLocaleString('uk-UA'));
    }
    if (metaParts.length) {
      const meta = document.createElement('div');
      meta.className = 'tg-homework-meta';
      meta.textContent = metaParts.join(' · ');
      card.appendChild(meta);
    }

    const links = document.createElement('div');
    links.className = 'tg-homework-links';
    appendHomeworkLink(links, { href: item.link_url, label: 'Відкрити лінк' });
    appendHomeworkFileButton(links, {
      href: item.file_path,
      label: item.file_name ? `Файл: ${item.file_name}` : 'Відкрити файл',
    });
    if (Array.isArray(item.assets)) {
      item.assets.forEach((asset) => {
        if (!asset) return;
        appendHomeworkFileButton(links, {
          href: asset.file_path,
          label: asset.name || asset.original_name || 'Відкрити файл',
        });
      });
    }
    if (links.children.length) card.appendChild(links);

    return card;
  }

  function bindScheduleHomeworkViewModal() {
    const modal = document.getElementById('tgHomeworkViewModal');
    if (!modal || modal.dataset.tgHomeworkViewModalBound === '1') return;
    modal.dataset.tgHomeworkViewModalBound = '1';
    const meta = modal.querySelector('[data-tg-homework-view-meta]');
    const list = modal.querySelector('[data-tg-homework-view-list]');

    function closeModal() {
      if (modal.hidden) return;
      modal.hidden = true;
      unlockPageScroll(modal);
    }

    function openModal(button) {
      if (!button || !list) return;
      let items = [];
      try {
        const parsed = JSON.parse(button.dataset.tgHomeworkItems || '[]');
        items = Array.isArray(parsed) ? parsed : [];
      } catch (_error) {
        items = [];
      }
      list.innerHTML = '';
      if (meta) meta.textContent = button.dataset.tgHomeworkViewMeta || 'Пара';
      if (!items.length) {
        const empty = document.createElement('div');
        empty.className = 'tg-muted';
        empty.textContent = 'ДЗ для цієї пари не знайшов.';
        list.appendChild(empty);
      } else {
        items.forEach((item) => {
          list.appendChild(renderHomeworkViewItem(item || {}));
        });
      }
      modal.hidden = false;
      lockPageScroll(modal);
    }

    document.querySelectorAll('[data-tg-homework-view]').forEach((button) => {
      if (button.dataset.tgHomeworkViewBound === '1') return;
      button.dataset.tgHomeworkViewBound = '1';
      button.addEventListener('click', () => openModal(button));
    });
    modal.querySelectorAll('[data-tg-homework-view-close]').forEach((button) => {
      button.addEventListener('click', closeModal);
    });
    modal.addEventListener('click', (event) => {
      if (event.target === modal) closeModal();
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && !modal.hidden) closeModal();
    });
  }

  function getPreviewKind(href, label) {
    const value = `${href || ''} ${label || ''}`.toLowerCase();
    if (/\.(?:png|jpe?g|gif)(?:[?#]|$)/.test(value)) return 'image';
    if (/\.pdf(?:[?#]|$)/.test(value)) return 'pdf';
    return 'download';
  }

  function bindScheduleFilePreviewModal() {
    const modal = document.getElementById('tgFilePreviewModal');
    if (!modal || modal.dataset.tgFilePreviewModalBound === '1') return;
    modal.dataset.tgFilePreviewModalBound = '1';
    const title = modal.querySelector('[data-tg-file-preview-title]');
    const meta = modal.querySelector('[data-tg-file-preview-meta]');
    const body = modal.querySelector('[data-tg-file-preview-body]');
    const download = modal.querySelector('[data-tg-file-preview-download]');

    function closeModal() {
      if (modal.hidden) return;
      modal.hidden = true;
      if (body) body.innerHTML = '';
      if (hasOpenTgModal(modal)) return;
      unlockPageScroll(modal);
    }

    function openModal(button) {
      const href = button && button.dataset ? button.dataset.tgFileHref : '';
      const safeHref = resolveHomeworkHref(href, { uploadsOnly: true });
      if (!safeHref || !body) return;
      const label = button.dataset.tgFileLabel || 'Файл';
      const previewHref = buildHomeworkUrl(safeHref, { preview: '1' });
      const downloadHref = buildHomeworkUrl(safeHref, { download: '1' }) || safeHref;
      const previewKind = getPreviewKind(safeHref, label);
      if (title) title.textContent = label.replace(/^Файл:\s*/i, '') || 'Файл';
      if (meta) {
        meta.textContent = previewKind === 'download'
          ? 'Для цього формату доступне завантаження.'
          : 'Предперегляд без виходу з Telegram.';
      }
      if (download) {
        download.href = downloadHref;
        download.setAttribute('download', '');
      }
      body.innerHTML = '';
      if (previewKind === 'image') {
        const image = document.createElement('img');
        image.className = 'tg-file-preview-image';
        image.src = previewHref;
        image.alt = label;
        body.appendChild(image);
      } else if (previewKind === 'pdf') {
        const frame = document.createElement('iframe');
        frame.className = 'tg-file-preview-frame';
        frame.src = previewHref;
        frame.title = label;
        body.appendChild(frame);
      } else {
        const empty = document.createElement('div');
        empty.className = 'tg-file-preview-empty';
        empty.textContent = 'Предперегляд цього файлу недоступний у mini app. Його можна завантажити кнопкою нижче.';
        body.appendChild(empty);
      }
      modal.hidden = false;
      lockPageScroll(modal);
    }

    modal._tgOpenFilePreview = openModal;
    if (document.documentElement.dataset.tgFilePreviewClickBound !== '1') {
      document.documentElement.dataset.tgFilePreviewClickBound = '1';
      document.addEventListener('click', (event) => {
        const button = event.target && event.target.closest ? event.target.closest('[data-tg-file-preview-open]') : null;
        if (!button) return;
        const currentModal = document.getElementById('tgFilePreviewModal');
        if (!currentModal || typeof currentModal._tgOpenFilePreview !== 'function') return;
        event.preventDefault();
        currentModal._tgOpenFilePreview(button);
      });
    }
    modal.querySelectorAll('[data-tg-file-preview-close]').forEach((button) => {
      button.addEventListener('click', closeModal);
    });
    modal.addEventListener('click', (event) => {
      if (event.target === modal) closeModal();
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && !modal.hidden) closeModal();
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
  bindRegisterForms();
  bindSubjectPickers();
  bindFileInputs();
  bindScheduleHomeworkModal();
  bindScheduleHomeworkViewModal();
  bindScheduleFilePreviewModal();
  primeFastPages();
  syncTelegramSession();
})();
