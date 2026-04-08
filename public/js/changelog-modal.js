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
  const BASE_BACKDROP_Z_INDEX = 1070;
  const BASE_MODAL_Z_INDEX = 1080;
  const MODAL_LAYER_STEP = 20;
  const SCROLL_LOCK_STATE_ATTR = 'data-studerria-scroll-lock';
  const SCROLL_LOCK_VALUE_ATTR = 'data-studerria-scroll-lock-overflow-value';
  const SCROLL_LOCK_PRIORITY_ATTR = 'data-studerria-scroll-lock-overflow-priority';
  const NO_BLUR_STATE_ATTR = 'data-studerria-no-blur-active';
  const MODAL_BLUR_STATE_ATTR = 'data-studerria-modal-blur-active';
  const EMPTY_STYLE_TOKEN = '__studerria-empty-style__';
  const APPLE_WEBVIEW_CLASS = 'studerria-apple-webview';
  const MODAL_FALLBACK_OPEN_CLASS = 'studerria-modal-fallback-open';
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
    '.schedule-card',
    '.admin-nav',
    '.admin-viewas-form',
    '.admin-sidebar',
    '.admin-sidebar-inner',
    '.admin-header-rail',
    '.admin-course-chip',
    '.admin-topbar-btn',
    '.session-health-chip',
    '.bulk-bar',
    '.flash-alert',
    '.admin-toast',
    '.admin-preview-form',
    '.role-studio-role-card',
    '.dropdown-menu'
  ].join(', ');
  const NO_BLUR_STYLE_FIELDS = [
    ['-webkit-backdrop-filter', 'studerriaNoBlurWebkitBackdropValue', 'studerriaNoBlurWebkitBackdropPriority'],
    ['backdrop-filter', 'studerriaNoBlurBackdropValue', 'studerriaNoBlurBackdropPriority'],
    ['filter', 'studerriaNoBlurFilterValue', 'studerriaNoBlurFilterPriority']
  ];
  const MODAL_BLUR_STYLE_FIELDS = [
    ['-webkit-filter', 'studerriaModalBlurWebkitFilterValue', 'studerriaModalBlurWebkitFilterPriority'],
    ['filter', 'studerriaModalBlurFilterValue', 'studerriaModalBlurFilterPriority'],
    ['transition', 'studerriaModalBlurTransitionValue', 'studerriaModalBlurTransitionPriority'],
    ['will-change', 'studerriaModalBlurWillChangeValue', 'studerriaModalBlurWillChangePriority']
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

  function isAtlasLikeAppleWebView() {
    const navigatorRef = window.navigator || {};
    const userAgent = String(navigatorRef.userAgent || '');
    const vendor = String(navigatorRef.vendor || '');
    const platform = String(navigatorRef.platform || '');
    const isApplePlatform =
      /(Mac|iPhone|iPad|iPod)/i.test(platform) || /(Macintosh|iPhone|iPad|iPod)/i.test(userAgent);
    const isAppleEngine = /AppleWebKit/i.test(userAgent) || /Apple/i.test(vendor);
    const isExcludedBrowser =
      /(Chrome|Chromium|CriOS|Edg|EdgiOS|OPR|OPT|SamsungBrowser|DuckDuckGo|Firefox|FxiOS)/i.test(
        userAgent
      );
    const isAtlasToken = /(Atlas|ChatGPT)/i.test(userAgent);
    const hasSafariGlobal = typeof window.safari !== 'undefined';

    return Boolean(isAtlasToken || (isApplePlatform && isAppleEngine && !isExcludedBrowser && !hasSafariGlobal));
  }

  function primeEnvironmentFlags() {
    const body = document.body;
    if (!(body instanceof HTMLElement)) {
      return false;
    }

    const shouldUseAppleWebViewFallback = isAtlasLikeAppleWebView();
    body.classList.toggle(APPLE_WEBVIEW_CLASS, shouldUseAppleWebViewFallback);
    return shouldUseAppleWebViewFallback;
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

  function syncModalLayers() {
    cleanupBackdrop();

    const visibleModals = Array.from(document.querySelectorAll('.modal.show')).filter(
      (modal) => modal instanceof HTMLElement
    );
    visibleModals.forEach((modal, index) => {
      modal.style.zIndex = String(BASE_MODAL_Z_INDEX + (index * MODAL_LAYER_STEP));
    });

    const backdrops = Array.from(document.querySelectorAll('.modal-backdrop'));
    backdrops.forEach((backdrop, index) => {
      if (!(backdrop instanceof HTMLElement)) {
        return;
      }

      backdrop.style.pointerEvents = index === backdrops.length - 1 ? 'auto' : 'none';
      backdrop.style.opacity = 'var(--bs-backdrop-opacity, 0.42)';
      backdrop.style.zIndex = String(BASE_BACKDROP_Z_INDEX + (index * MODAL_LAYER_STEP));
      backdrop.style.webkitBackdropFilter = 'none';
      backdrop.style.backdropFilter = 'none';
    });

    const activeBackdrop = backdrops.length ? backdrops[backdrops.length - 1] : null;
    if (activeBackdrop instanceof HTMLElement) {
      activeBackdrop.classList.add(BACKDROP_CLASS);
    }
  }

  function portalModal(modal) {
    if (!(modal instanceof HTMLElement) || !document.body || modal.parentElement === document.body) {
      return;
    }

    document.body.appendChild(modal);
  }

  function primeStaticModals() {
    document.querySelectorAll('.modal').forEach((modal) => {
      portalModal(modal);
    });
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

  function getModalBlurFallbackValue() {
    const body = document.body;
    const isLightTheme = body instanceof HTMLElement && body.classList.contains('theme-light');
    return isLightTheme
      ? 'blur(16px) saturate(0.98) brightness(0.98)'
      : 'blur(18px) saturate(0.94) brightness(0.94)';
  }

  function isModalBlurFallbackTarget(target) {
    return (
      target instanceof HTMLElement &&
      target.parentElement === document.body &&
      !target.matches('.modal, .modal-backdrop, script, style, link, template, noscript')
    );
  }

  function applyModalBlurFallback(target) {
    if (!isModalBlurFallbackTarget(target) || target.getAttribute(MODAL_BLUR_STATE_ATTR) === '1') {
      return;
    }

    const blurValue = getModalBlurFallbackValue();

    MODAL_BLUR_STYLE_FIELDS.forEach(([cssProperty, valueKey, priorityKey]) => {
      const inlineValue = target.style.getPropertyValue(cssProperty);
      const inlinePriority = target.style.getPropertyPriority(cssProperty);
      target.dataset[valueKey] = inlineValue || EMPTY_STYLE_TOKEN;
      target.dataset[priorityKey] = inlinePriority || EMPTY_STYLE_TOKEN;
    });

    target.style.setProperty('-webkit-filter', blurValue, 'important');
    target.style.setProperty('filter', blurValue, 'important');
    target.style.setProperty('transition', 'filter 220ms ease, opacity 220ms ease', 'important');
    target.style.setProperty('will-change', 'filter', 'important');
    target.setAttribute(MODAL_BLUR_STATE_ATTR, '1');
  }

  function restoreModalBlurFallback(target) {
    if (!(target instanceof HTMLElement) || target.getAttribute(MODAL_BLUR_STATE_ATTR) !== '1') {
      return;
    }

    MODAL_BLUR_STYLE_FIELDS.forEach(([cssProperty, valueKey, priorityKey]) => {
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

    target.removeAttribute(MODAL_BLUR_STATE_ATTR);
  }

  function syncModalBlurFallback(forceOpen) {
    const shouldOpen = typeof forceOpen === 'boolean' ? forceOpen : hasVisibleModal();

    if (shouldOpen) {
      Array.from(document.body?.children || []).forEach((target) => {
        applyModalBlurFallback(target);
      });
      return;
    }

    document.querySelectorAll(`[${MODAL_BLUR_STATE_ATTR}="1"]`).forEach((target) => {
      restoreModalBlurFallback(target);
    });
  }

  function syncNoBlurTargets(forceOpen) {
    if (forceOpen) {
      const targets = new Set();

      document.querySelectorAll(NO_BLUR_SELECTOR).forEach((target) => {
        targets.add(target);
      });

      document.body?.querySelectorAll('*').forEach((target) => {
        if (!(target instanceof HTMLElement)) {
          return;
        }

        if (target.classList.contains('modal-backdrop') || target.closest('.modal')) {
          return;
        }

        const computedStyles = window.getComputedStyle(target);
        const computedBackdrop =
          computedStyles.getPropertyValue('backdrop-filter') ||
          computedStyles.getPropertyValue('-webkit-backdrop-filter');
        const computedFilter = computedStyles.getPropertyValue('filter');

        if (
          (computedBackdrop && computedBackdrop !== 'none') ||
          (computedFilter && computedFilter.includes('blur('))
        ) {
          targets.add(target);
        }
      });

      targets.forEach((target) => {
        if (!(target instanceof HTMLElement)) {
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

    primeEnvironmentFlags();
    const useModalBlurFallback = true;
    const shouldOpen = typeof forceOpen === 'boolean' ? forceOpen : hasVisibleModal();
    const changelogIsVisible = hasVisibleChangelogModal();

    if (shouldOpen) {
      body.classList.add(BOOTSTRAP_OPEN_CLASS);
      body.classList.toggle(MODAL_FALLBACK_OPEN_CLASS, useModalBlurFallback);
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
      if (useModalBlurFallback) {
        syncModalBlurFallback(true);
        syncNoBlurTargets(false);
      } else {
        syncModalBlurFallback(false);
        syncNoBlurTargets(true);
      }
      return;
    }

    body.classList.remove(MODAL_FALLBACK_OPEN_CLASS);
    syncModalBlurFallback(false);
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

        portalModal(event.target);
        const isChangelogModal = isChangelogModalElement(event.target);
        syncBodyOpenClasses(true, isChangelogModal);
        requestAnimationFrame(syncModalLayers);
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
        syncModalLayers();
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
          syncModalLayers();
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
        requestAnimationFrame(syncModalLayers);
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
      requestAnimationFrame(syncModalLayers);
    });

    modal.addEventListener('shown.bs.modal', () => {
      syncBodyOpenClasses(true, true);
      syncModalLayers();
    });

    modal.addEventListener('hidden.bs.modal', () => {
      syncBodyOpenClasses();
      requestAnimationFrame(syncModalLayers);
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
    primeEnvironmentFlags();
    bindGlobalModalSync();
    primeStaticModals();

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
