(() => {
  if (window.__studerriaChangelogModalBoot === true) {
    return;
  }
  window.__studerriaChangelogModalBoot = true;

  const MODAL_SELECTOR = '[data-studerria-modal="changelog"]';
  const BACKDROP_CLASS = 'studerria-changelog-backdrop';
  const BODY_OPEN_CLASS = 'studerria-changelog-open';
  const BOOTSTRAP_OPEN_CLASS = 'modal-open';
  const GLOBAL_SYNC_BOOT_FLAG = '__studerriaGlobalModalSyncBoot';
  const SCROLL_LOCK_STATE_ATTR = 'data-studerria-scroll-lock';
  const SCROLL_LOCK_VALUE_ATTR = 'data-studerria-scroll-lock-overflow-value';
  const SCROLL_LOCK_PRIORITY_ATTR = 'data-studerria-scroll-lock-overflow-priority';
  const NO_BLUR_STATE_ATTR = 'data-studerria-no-blur-active';
  const EMPTY_STYLE_TOKEN = '__studerria-empty-style__';
  const NO_BLUR_SELECTOR = [
    '.glass',
    '.glass-card',
    '.glass-panel',
    '.glass-inset',
    '.glass-dock',
    '.surface',
    '.surface--elevated',
    '.card',
    '.topbar',
    '.app-footer',
    '.app-footer .footer-meta',
    '.schedule-content',
    '.schedule-shell',
    '.week-pager',
    '.cockpit-page',
    '.week-hero',
    '.schedule-panel',
    '.day-card',
    '.density-summary',
    '.week-rail',
    '.schedule-card'
  ].join(', ');
  const NO_BLUR_STYLE_FIELDS = [
    ['-webkit-backdrop-filter', 'studerriaNoBlurWebkitBackdropValue', 'studerriaNoBlurWebkitBackdropPriority'],
    ['backdrop-filter', 'studerriaNoBlurBackdropValue', 'studerriaNoBlurBackdropPriority'],
    ['filter', 'studerriaNoBlurFilterValue', 'studerriaNoBlurFilterPriority']
  ];

  function getModal() {
    return document.querySelector(MODAL_SELECTOR);
  }

  function hasVisibleModal() {
    return document.querySelector('.modal.show') instanceof HTMLElement;
  }

  function hasVisibleChangelogModal() {
    return document.querySelector(`${MODAL_SELECTOR}.show`) instanceof HTMLElement;
  }

  function cleanupBackdrop() {
    document.querySelectorAll(`.${BACKDROP_CLASS}`).forEach((backdrop) => {
      if (!(backdrop instanceof HTMLElement)) {
        return;
      }
      backdrop.classList.remove(BACKDROP_CLASS);
      backdrop.style.pointerEvents = '';
      backdrop.style.opacity = '';
      backdrop.style.zIndex = '';
      backdrop.style.webkitBackdropFilter = '';
      backdrop.style.backdropFilter = '';
    });
  }

  function syncBackdrop() {
    cleanupBackdrop();

    const backdrops = Array.from(document.querySelectorAll('.modal-backdrop'));
    const activeBackdrop = backdrops.length ? backdrops[backdrops.length - 1] : null;

    if (!(activeBackdrop instanceof HTMLElement)) {
      return;
    }

    activeBackdrop.classList.add(BACKDROP_CLASS);
    activeBackdrop.style.pointerEvents = 'auto';
    activeBackdrop.style.opacity = 'var(--bs-backdrop-opacity, 0.42)';
    activeBackdrop.style.zIndex = '1075';
    activeBackdrop.style.webkitBackdropFilter = 'none';
    activeBackdrop.style.backdropFilter = 'none';
  }

  function portalModal(modal) {
    if (!(modal instanceof HTMLElement) || !document.body || modal.parentElement === document.body) {
      return;
    }

    document.body.appendChild(modal);
  }

  function applyInlineNoBlur(target) {
    if (!(target instanceof HTMLElement) || target.getAttribute(NO_BLUR_STATE_ATTR) === '1') {
      return;
    }

    NO_BLUR_STYLE_FIELDS.forEach(([cssProperty, valueKey, priorityKey]) => {
      const inlineValue = target.style.getPropertyValue(cssProperty);
      const inlinePriority = target.style.getPropertyPriority(cssProperty);
      target.dataset[valueKey] = inlineValue || EMPTY_STYLE_TOKEN;
      target.dataset[priorityKey] = inlinePriority || EMPTY_STYLE_TOKEN;
      target.style.setProperty(cssProperty, 'none', 'important');
    });

    target.setAttribute(NO_BLUR_STATE_ATTR, '1');
  }

  function restoreInlineNoBlur(target) {
    if (!(target instanceof HTMLElement) || target.getAttribute(NO_BLUR_STATE_ATTR) !== '1') {
      return;
    }

    NO_BLUR_STYLE_FIELDS.forEach(([cssProperty, valueKey, priorityKey]) => {
      const inlineValue = target.dataset[valueKey];
      const inlinePriority = target.dataset[priorityKey];

      if (inlineValue && inlineValue !== EMPTY_STYLE_TOKEN) {
        target.style.setProperty(
          cssProperty,
          inlineValue,
          inlinePriority && inlinePriority !== EMPTY_STYLE_TOKEN ? inlinePriority : ''
        );
      } else {
        target.style.removeProperty(cssProperty);
      }

      delete target.dataset[valueKey];
      delete target.dataset[priorityKey];
    });

    target.removeAttribute(NO_BLUR_STATE_ATTR);
  }

  function syncNoBlurTargets(forceOpen) {
    if (forceOpen) {
      document.querySelectorAll(NO_BLUR_SELECTOR).forEach((target) => {
        if (!(target instanceof HTMLElement)) {
          return;
        }

        if (target.classList.contains('modal-backdrop') || target.closest('.modal')) {
          return;
        }

        applyInlineNoBlur(target);
      });
      return;
    }

    document.querySelectorAll(`[${NO_BLUR_STATE_ATTR}="1"]`).forEach((target) => {
      restoreInlineNoBlur(target);
    });
  }

  function syncBodyOpenClasses(forceOpen, includeChangelogClass = false) {
    const body = document.body;
    if (!(body instanceof HTMLElement)) {
      return;
    }

    const shouldOpen = typeof forceOpen === 'boolean' ? forceOpen : hasVisibleModal();
    const changelogIsVisible = hasVisibleChangelogModal();

    if (shouldOpen) {
      body.classList.add(BOOTSTRAP_OPEN_CLASS);
      if (includeChangelogClass || changelogIsVisible) {
        body.classList.add(BODY_OPEN_CLASS);
      } else {
        body.classList.remove(BODY_OPEN_CLASS);
      }
      const root = document.documentElement;
      if (root instanceof HTMLElement && root.getAttribute(SCROLL_LOCK_STATE_ATTR) !== '1') {
        root.setAttribute(SCROLL_LOCK_STATE_ATTR, '1');
        root.setAttribute(
          SCROLL_LOCK_VALUE_ATTR,
          root.style.getPropertyValue('overflow') || EMPTY_STYLE_TOKEN
        );
        root.setAttribute(
          SCROLL_LOCK_PRIORITY_ATTR,
          root.style.getPropertyPriority('overflow') || EMPTY_STYLE_TOKEN
        );
      }
      if (root instanceof HTMLElement) {
        root.style.setProperty('overflow', 'hidden', 'important');
      }
      syncNoBlurTargets(true);
      return;
    }

    body.classList.remove(BODY_OPEN_CLASS);
    body.classList.remove(BOOTSTRAP_OPEN_CLASS);
    const root = document.documentElement;
    if (root instanceof HTMLElement && root.getAttribute(SCROLL_LOCK_STATE_ATTR) === '1') {
      const previousValue = root.getAttribute(SCROLL_LOCK_VALUE_ATTR);
      const previousPriority = root.getAttribute(SCROLL_LOCK_PRIORITY_ATTR);
      if (previousValue && previousValue !== EMPTY_STYLE_TOKEN) {
        root.style.setProperty(
          'overflow',
          previousValue,
          previousPriority && previousPriority !== EMPTY_STYLE_TOKEN ? previousPriority : ''
        );
      } else {
        root.style.removeProperty('overflow');
      }
      root.removeAttribute(SCROLL_LOCK_STATE_ATTR);
      root.removeAttribute(SCROLL_LOCK_VALUE_ATTR);
      root.removeAttribute(SCROLL_LOCK_PRIORITY_ATTR);
    }
    syncNoBlurTargets(false);
  }

  function isModalElement(node) {
    return node instanceof HTMLElement && node.classList.contains('modal');
  }

  function isChangelogModalElement(node) {
    return node instanceof HTMLElement && node.matches(MODAL_SELECTOR);
  }

  function bindGlobalModalSync() {
    if (window[GLOBAL_SYNC_BOOT_FLAG] === true) {
      return;
    }
    window[GLOBAL_SYNC_BOOT_FLAG] = true;

    document.addEventListener(
      'show.bs.modal',
      (event) => {
        if (!isModalElement(event.target)) {
          return;
        }

        const isChangelogModal = isChangelogModalElement(event.target);
        syncBodyOpenClasses(true, isChangelogModal);
        if (isChangelogModal) {
          requestAnimationFrame(syncBackdrop);
          return;
        }
        cleanupBackdrop();
      },
      true
    );

    document.addEventListener(
      'shown.bs.modal',
      (event) => {
        if (!isModalElement(event.target)) {
          return;
        }

        const isChangelogModal = isChangelogModalElement(event.target);
        syncBodyOpenClasses(true, isChangelogModal);
        if (isChangelogModal) {
          syncBackdrop();
          return;
        }
        cleanupBackdrop();
      },
      true
    );

    document.addEventListener(
      'hide.bs.modal',
      (event) => {
        if (!isModalElement(event.target)) {
          return;
        }

        requestAnimationFrame(() => {
          syncBodyOpenClasses();
        });
      },
      true
    );

    document.addEventListener(
      'hidden.bs.modal',
      (event) => {
        if (!isModalElement(event.target)) {
          return;
        }

        syncBodyOpenClasses();
        if (hasVisibleChangelogModal()) {
          requestAnimationFrame(syncBackdrop);
          return;
        }

        cleanupBackdrop();
      },
      true
    );
  }

  function primeModal(modal) {
    if (!(modal instanceof HTMLElement) || modal.dataset.studerriaChangelogReady === '1') {
      return;
    }

    modal.dataset.studerriaChangelogReady = '1';
    portalModal(modal);
    modal.style.zIndex = '1080';
    modal.style.overscrollBehavior = 'contain';
    modal.style.touchAction = 'pan-y';

    const dialog = modal.querySelector('.modal-dialog');
    if (dialog instanceof HTMLElement) {
      dialog.style.margin = 'min(1rem, 2vh) auto';
    }

    const content = modal.querySelector('.modal-content');
    if (content instanceof HTMLElement) {
      content.style.pointerEvents = 'auto';
    }

    const body = modal.querySelector('.modal-body');
    if (body instanceof HTMLElement) {
      body.style.overflowY = 'auto';
      body.style.overscrollBehavior = 'contain';
      body.style.touchAction = 'pan-y';
      body.style.webkitOverflowScrolling = 'touch';
    }

    modal.addEventListener('show.bs.modal', () => {
      portalModal(modal);
      syncBodyOpenClasses(true, true);
      requestAnimationFrame(syncBackdrop);
    });

    modal.addEventListener('shown.bs.modal', () => {
      syncBodyOpenClasses(true, true);
      syncBackdrop();
    });

    modal.addEventListener('hidden.bs.modal', () => {
      syncBodyOpenClasses();
      if (hasVisibleChangelogModal()) {
        requestAnimationFrame(syncBackdrop);
        return;
      }
      cleanupBackdrop();
    });

    modal.addEventListener('pointerdown', (event) => {
      if (event.target !== modal) {
        return;
      }

      if (modal.getAttribute('data-bs-backdrop') === 'static') {
        return;
      }

      const instance = window.bootstrap?.Modal?.getInstance(modal);
      if (instance) {
        instance.hide();
      }
    });
  }

  function init() {
    bindGlobalModalSync();

    const modal = getModal();
    if (!(modal instanceof HTMLElement)) {
      return;
    }

    primeModal(modal);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
