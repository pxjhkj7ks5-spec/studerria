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
  const MODAL_FALLBACK_SCENE_ID = 'studerriaModalFallbackScene';
  const MODAL_FALLBACK_SCENE_CLASS = 'studerria-modal-fallback-scene';
  const MODAL_BLUR_CLONE_ATTR = 'data-studerria-modal-blur-clone';
  const MODAL_BLUR_CLONE_SOURCE_ATTR = 'data-studerria-modal-blur-clone-source';
  const MODAL_BLUR_TRANSITION_MS = 340;
  const MODAL_BLUR_CLEANUP_DELAY_MS = MODAL_BLUR_TRANSITION_MS + 80;
  const MODAL_BLUR_TRANSITION_VALUE = [
    `-webkit-filter ${MODAL_BLUR_TRANSITION_MS}ms cubic-bezier(0.22, 1, 0.36, 1)`,
    `filter ${MODAL_BLUR_TRANSITION_MS}ms cubic-bezier(0.22, 1, 0.36, 1)`,
    'opacity 260ms ease-out'
  ].join(', ');
  const MODAL_BACKDROP_TRANSITION_VALUE = [
    `opacity ${MODAL_BLUR_TRANSITION_MS}ms cubic-bezier(0.22, 1, 0.36, 1)`,
    `background-color ${MODAL_BLUR_TRANSITION_MS}ms cubic-bezier(0.22, 1, 0.36, 1)`
  ].join(', ');
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
    ['opacity', 'studerriaModalBlurOpacityValue', 'studerriaModalBlurOpacityPriority'],
    ['zoom', 'studerriaModalBlurZoomValue', 'studerriaModalBlurZoomPriority'],
    ['transform-origin', 'studerriaModalBlurTransformOriginValue', 'studerriaModalBlurTransformOriginPriority'],
    ['transition', 'studerriaModalBlurTransitionValue', 'studerriaModalBlurTransitionPriority'],
    ['will-change', 'studerriaModalBlurWillChangeValue', 'studerriaModalBlurWillChangePriority']
  ];
  const modalBlurCleanupTimers = new WeakMap();
  let modalFallbackSceneCleanupTimer = 0;
  let modalBlurCloneCleanupTimer = 0;

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
      backdrop.style.background = '';
      backdrop.style.backgroundColor = '';
      backdrop.style.removeProperty('--bs-backdrop-bg');
      backdrop.style.transition = '';
      backdrop.style.webkitBackdropFilter = '';
      backdrop.style.backdropFilter = '';
    });
  }

  function syncModalLayers() {
    cleanupBackdrop();
    const fallbackBackdropUsesTint =
      document.body instanceof HTMLElement && document.body.classList.contains(MODAL_FALLBACK_OPEN_CLASS);

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
      backdrop.style.opacity = fallbackBackdropUsesTint ? '1' : 'var(--bs-backdrop-opacity, 0.42)';
      backdrop.style.zIndex = String(BASE_BACKDROP_Z_INDEX + (index * MODAL_LAYER_STEP));
      if (fallbackBackdropUsesTint) {
        const fallbackBackdropColor = getModalFallbackBackdropColor();
        backdrop.style.setProperty('--bs-backdrop-bg', fallbackBackdropColor);
        backdrop.style.background = fallbackBackdropColor;
        backdrop.style.backgroundColor = fallbackBackdropColor;
        backdrop.style.transition = MODAL_BACKDROP_TRANSITION_VALUE;
      }
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

  function getModalFallbackSceneOpacity() {
    const body = document.body;
    const isLightTheme = body instanceof HTMLElement && body.classList.contains('theme-light');
    return isLightTheme ? '0.9' : '0.82';
  }

  function isModalBlurFallbackTarget(target) {
    if (isModalBlurSceneTarget(target)) {
      return true;
    }
    if (isModalBlurCloneTarget(target)) {
      return true;
    }
    if (document.body instanceof HTMLElement && document.body.classList.contains(APPLE_WEBVIEW_CLASS)) {
      return false;
    }
    return isModalBlurBackgroundTarget(target);
  }

  function isModalBlurBackgroundTarget(target) {
    return target instanceof HTMLElement && (target.id === 'dynamic-bg' || target.id === 'studerriaBg');
  }

  function isModalBlurSceneTarget(target) {
    return target instanceof HTMLElement && target.id === MODAL_FALLBACK_SCENE_ID;
  }

  function isModalBlurCloneTarget(target) {
    return target instanceof HTMLElement && target.getAttribute(MODAL_BLUR_CLONE_ATTR) === '1';
  }

  function clearModalFallbackSceneCleanupTimer() {
    if (modalFallbackSceneCleanupTimer) {
      window.clearTimeout(modalFallbackSceneCleanupTimer);
      modalFallbackSceneCleanupTimer = 0;
    }
  }

  function getModalFallbackScene() {
    return document.getElementById(MODAL_FALLBACK_SCENE_ID);
  }

  function configureModalFallbackSceneBase(scene) {
    if (!(scene instanceof HTMLElement)) {
      return;
    }

    scene.style.position = 'fixed';
    scene.style.left = '0';
    scene.style.top = '0';
    scene.style.width = `${Math.max(window.innerWidth || 0, 1)}px`;
    scene.style.height = `${Math.max(window.innerHeight || 0, 1)}px`;
    scene.style.overflow = 'hidden';
    scene.style.pointerEvents = 'none';
    scene.style.zIndex = '0';
    scene.style.transformOrigin = 'top left';
    scene.style.zoom = '1';
  }

  function computeViewportFitZoomCompensation(target) {
    if (!(target instanceof HTMLElement)) {
      return null;
    }

    const rect = target.getBoundingClientRect();
    const renderedWidth = Math.max(Number(rect.width) || 0, 1);
    const renderedHeight = Math.max(Number(rect.height) || 0, 1);
    const compensation = Math.max(
      Math.max(window.innerWidth || 1, 1) / renderedWidth,
      Math.max(window.innerHeight || 1, 1) / renderedHeight
    );

    if (!Number.isFinite(compensation) || compensation <= 0 || Math.abs(compensation - 1) < 0.001) {
      return null;
    }

    return compensation;
  }

  function syncModalFallbackSceneGeometry(scene) {
    if (!(scene instanceof HTMLElement)) {
      return;
    }

    configureModalFallbackSceneBase(scene);
    const compensation = computeViewportFitZoomCompensation(scene);
    if (compensation) {
      scene.style.zoom = compensation.toFixed(6);
    }
  }

  function shouldWrapModalFallbackNode(node) {
    if (!(node instanceof HTMLElement) || isModalBlurSceneTarget(node)) {
      return false;
    }
    if (isModalBlurBackgroundTarget(node)) {
      return false;
    }
    if (node.classList.contains('modal') || node.classList.contains('modal-backdrop')) {
      return false;
    }
    return !['SCRIPT', 'STYLE', 'LINK', 'TEMPLATE'].includes(node.tagName);
  }

  function ensureModalFallbackScene() {
    const body = document.body;
    if (!(body instanceof HTMLElement) || !body.classList.contains(APPLE_WEBVIEW_CLASS)) {
      return null;
    }

    clearModalFallbackSceneCleanupTimer();
    let scene = getModalFallbackScene();
    if (!(scene instanceof HTMLElement)) {
      scene = document.createElement('div');
      scene.id = MODAL_FALLBACK_SCENE_ID;
      scene.className = MODAL_FALLBACK_SCENE_CLASS;
      body.insertBefore(scene, body.firstChild);
    }

    Array.from(body.children).forEach((child) => {
      if (shouldWrapModalFallbackNode(child)) {
        scene.appendChild(child);
      }
    });

    syncModalFallbackSceneGeometry(scene);
    return scene;
  }

  function dismantleModalFallbackScene() {
    const body = document.body;
    const scene = getModalFallbackScene();
    if (!(body instanceof HTMLElement) || !(scene instanceof HTMLElement)) {
      return;
    }

    while (scene.firstChild) {
      body.insertBefore(scene.firstChild, scene);
    }
    scene.remove();
  }

  function scheduleModalFallbackSceneCleanup() {
    const scene = getModalFallbackScene();
    if (!(scene instanceof HTMLElement)) {
      return;
    }

    clearModalFallbackSceneCleanupTimer();
    modalFallbackSceneCleanupTimer = window.setTimeout(() => {
      if (hasVisibleModal()) {
        modalFallbackSceneCleanupTimer = 0;
        return;
      }
      dismantleModalFallbackScene();
      modalFallbackSceneCleanupTimer = 0;
    }, MODAL_BLUR_CLEANUP_DELAY_MS);
  }

  function clearModalBlurCloneCleanupTimer() {
    if (modalBlurCloneCleanupTimer) {
      window.clearTimeout(modalBlurCloneCleanupTimer);
      modalBlurCloneCleanupTimer = 0;
    }
  }

  function getModalBlurCloneForSource(sourceId) {
    if (!sourceId) {
      return null;
    }

    return document.querySelector(
      `[${MODAL_BLUR_CLONE_ATTR}="1"][${MODAL_BLUR_CLONE_SOURCE_ATTR}="${window.CSS?.escape ? window.CSS.escape(sourceId) : sourceId}"]`
    );
  }

  function configureModalBlurCloneBase(clone) {
    if (!(clone instanceof HTMLElement)) {
      return;
    }

    clone.style.position = 'fixed';
    clone.style.left = '0';
    clone.style.top = '0';
    clone.style.width = `${Math.max(window.innerWidth || 0, 1)}px`;
    clone.style.height = `${Math.max(window.innerHeight || 0, 1)}px`;
    clone.style.overflow = 'hidden';
    clone.style.pointerEvents = 'none';
    clone.style.zIndex = '-1';
    clone.style.transform = 'translateZ(0)';
    clone.style.transformOrigin = 'top left';
    clone.style.zoom = '1';
  }

  function syncModalBlurCloneGeometry(clone) {
    if (!(clone instanceof HTMLElement)) {
      return;
    }

    configureModalBlurCloneBase(clone);
    const rect = clone.getBoundingClientRect();
    const renderedWidth = Math.max(Number(rect.width) || 0, 1);
    const renderedHeight = Math.max(Number(rect.height) || 0, 1);
    const compensation = computeViewportFitZoomCompensation(clone);

    if (compensation) {
      clone.style.zoom = compensation.toFixed(6);
    }
  }

  function createModalBlurCloneFromSource(source) {
    if (!(source instanceof HTMLElement) || !source.id) {
      return null;
    }

    const clone = source.cloneNode(true);
    clone.removeAttribute('id');
    clone.setAttribute(MODAL_BLUR_CLONE_ATTR, '1');
    clone.setAttribute(MODAL_BLUR_CLONE_SOURCE_ATTR, source.id);
    clone.setAttribute('aria-hidden', 'true');
    clone.classList.add('studerria-modal-blur-clone');

    clone.querySelectorAll('#dynamicBgTrail, #studerriaBgParticles').forEach((node) => {
      node.removeAttribute('id');
    });

    configureModalBlurCloneBase(clone);
    return clone;
  }

  function ensureModalBlurClones() {
    const body = document.body;
    if (!(body instanceof HTMLElement) || !body.classList.contains(APPLE_WEBVIEW_CLASS)) {
      return;
    }

    clearModalBlurCloneCleanupTimer();
    Array.from(body.children).forEach((child) => {
      if (!isModalBlurBackgroundTarget(child)) {
        return;
      }

      let clone = getModalBlurCloneForSource(child.id);
      if (!(clone instanceof HTMLElement)) {
        clone = createModalBlurCloneFromSource(child);
        if (clone instanceof HTMLElement) {
          body.appendChild(clone);
        }
      }

      syncModalBlurCloneGeometry(clone);
    });
  }

  function scheduleModalBlurCloneCleanup() {
    clearModalBlurCloneCleanupTimer();
    modalBlurCloneCleanupTimer = window.setTimeout(() => {
      if (hasVisibleModal()) {
        modalBlurCloneCleanupTimer = 0;
        return;
      }

      document.querySelectorAll(`[${MODAL_BLUR_CLONE_ATTR}="1"]`).forEach((node) => {
        if (node instanceof HTMLElement) {
          node.remove();
        }
      });
      modalBlurCloneCleanupTimer = 0;
    }, MODAL_BLUR_CLEANUP_DELAY_MS);
  }

  function getModalFallbackBackdropColor() {
    const body = document.body;
    const isLightTheme = body instanceof HTMLElement && body.classList.contains('theme-light');
    return isLightTheme ? 'rgba(236, 242, 252, 0.14)' : 'rgba(7, 11, 24, 0.18)';
  }

  function readComputedZoom(target) {
    const zoomValue = Number.parseFloat(window.getComputedStyle(target).zoom || '1');
    return Number.isFinite(zoomValue) && zoomValue > 0 ? zoomValue : 1;
  }

  function readTargetRenderScale(target) {
    if (!(target instanceof HTMLElement)) {
      return { scaleX: 1, scaleY: 1 };
    }

    const probe = document.createElement('div');
    probe.style.position = 'absolute';
    probe.style.left = '0';
    probe.style.top = '0';
    probe.style.width = '100px';
    probe.style.height = '100px';
    probe.style.visibility = 'hidden';
    probe.style.pointerEvents = 'none';
    target.appendChild(probe);

    const probeRect = probe.getBoundingClientRect();
    probe.remove();

    return {
      scaleX: Math.max((Number(probeRect.width) || 100) / 100, 0.0001),
      scaleY: Math.max((Number(probeRect.height) || 100) / 100, 0.0001)
    };
  }

  function computeModalBlurZoomCompensation(target) {
    if (isModalBlurSceneTarget(target)) {
      return null;
    }
    const body = document.body;
    if (
      !(body instanceof HTMLElement) ||
      (body.classList.contains(APPLE_WEBVIEW_CLASS) && !isModalBlurCloneTarget(target)) ||
      !body.classList.contains('studerria-theme') ||
      window.innerWidth < 1200
    ) {
      return null;
    }

    const currentZoom = readComputedZoom(target);
    const renderScale = readTargetRenderScale(target);
    const dominantScale = Math.max(Math.min(renderScale.scaleX, renderScale.scaleY), 0.0001);
    const compensatedZoom = currentZoom / dominantScale;

    if (!Number.isFinite(compensatedZoom) || compensatedZoom <= 0 || Math.abs(compensatedZoom - currentZoom) < 0.001) {
      return null;
    }

    return compensatedZoom;
  }

  function restoreTrackedInlineStyle(target, cssProperty, valueKey, priorityKey) {
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
  }

  function clearModalBlurCleanupTimer(target) {
    const activeTimer = modalBlurCleanupTimers.get(target);
    if (activeTimer) {
      window.clearTimeout(activeTimer);
      modalBlurCleanupTimers.delete(target);
    }
  }

  function applyModalBlurFallback(target) {
    if (!isModalBlurFallbackTarget(target)) {
      return;
    }

    clearModalBlurCleanupTimer(target);
    const blurValue = getModalBlurFallbackValue();
    const sceneOpacity = getModalFallbackSceneOpacity();
    const isSceneTarget = isModalBlurSceneTarget(target);
    const isAlreadyActive = target.getAttribute(MODAL_BLUR_STATE_ATTR) === '1';

    if (!isAlreadyActive) {
      MODAL_BLUR_STYLE_FIELDS.forEach(([cssProperty, valueKey, priorityKey]) => {
        const inlineValue = target.style.getPropertyValue(cssProperty);
        const inlinePriority = target.style.getPropertyPriority(cssProperty);
        target.dataset[valueKey] = inlineValue || EMPTY_STYLE_TOKEN;
        target.dataset[priorityKey] = inlinePriority || EMPTY_STYLE_TOKEN;
      });
    }

    target.style.setProperty('transition', MODAL_BLUR_TRANSITION_VALUE, 'important');
    target.style.setProperty('will-change', 'filter, opacity', 'important');
    target.setAttribute(MODAL_BLUR_STATE_ATTR, '1');

    requestAnimationFrame(() => {
      if (target.getAttribute(MODAL_BLUR_STATE_ATTR) !== '1') {
        return;
      }

      const compensatedZoom = computeModalBlurZoomCompensation(target);
      if (compensatedZoom) {
        target.style.setProperty('zoom', compensatedZoom.toFixed(6), 'important');
        target.style.setProperty('transform-origin', 'top left', 'important');
      }

      if (isSceneTarget) {
        syncModalFallbackSceneGeometry(target);
        target.style.setProperty('-webkit-filter', blurValue, 'important');
        target.style.setProperty('filter', blurValue, 'important');
        target.style.setProperty('opacity', sceneOpacity, 'important');
        return;
      }

      target.style.setProperty('-webkit-filter', blurValue, 'important');
      target.style.setProperty('filter', blurValue, 'important');
      restoreTrackedInlineStyle(
        target,
        'opacity',
        'studerriaModalBlurOpacityValue',
        'studerriaModalBlurOpacityPriority'
      );
    });
  }

  function restoreModalBlurFallback(target) {
    if (!(target instanceof HTMLElement) || target.getAttribute(MODAL_BLUR_STATE_ATTR) !== '1') {
      return;
    }

    clearModalBlurCleanupTimer(target);
    target.style.setProperty('transition', MODAL_BLUR_TRANSITION_VALUE, 'important');
    target.style.setProperty('will-change', 'filter, opacity', 'important');

    [
      ['-webkit-filter', 'studerriaModalBlurWebkitFilterValue', 'studerriaModalBlurWebkitFilterPriority'],
      ['filter', 'studerriaModalBlurFilterValue', 'studerriaModalBlurFilterPriority'],
      ['opacity', 'studerriaModalBlurOpacityValue', 'studerriaModalBlurOpacityPriority']
    ].forEach(([cssProperty, valueKey, priorityKey]) => {
      restoreTrackedInlineStyle(target, cssProperty, valueKey, priorityKey);
    });

    const cleanupTimer = window.setTimeout(() => {
      [
        ['transition', 'studerriaModalBlurTransitionValue', 'studerriaModalBlurTransitionPriority'],
        ['will-change', 'studerriaModalBlurWillChangeValue', 'studerriaModalBlurWillChangePriority']
      ].forEach(([cssProperty, valueKey, priorityKey]) => {
        restoreTrackedInlineStyle(target, cssProperty, valueKey, priorityKey);
      });

      MODAL_BLUR_STYLE_FIELDS.forEach(([, valueKey, priorityKey]) => {
        delete target.dataset[valueKey];
        delete target.dataset[priorityKey];
      });

      target.removeAttribute(MODAL_BLUR_STATE_ATTR);
      modalBlurCleanupTimers.delete(target);
    }, MODAL_BLUR_CLEANUP_DELAY_MS);

    modalBlurCleanupTimers.set(target, cleanupTimer);
  }

  function syncModalBlurFallback(forceOpen) {
    const shouldOpen = typeof forceOpen === 'boolean' ? forceOpen : hasVisibleModal();

    if (shouldOpen) {
      ensureModalFallbackScene();
      ensureModalBlurClones();
      Array.from(document.body?.children || []).forEach((target) => {
        applyModalBlurFallback(target);
      });
      return;
    }

    document.querySelectorAll(`[${MODAL_BLUR_STATE_ATTR}="1"]`).forEach((target) => {
      restoreModalBlurFallback(target);
    });
    scheduleModalFallbackSceneCleanup();
    scheduleModalBlurCloneCleanup();
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
      window.requestAnimationFrame(() => {
        window.dispatchEvent(new Event('resize'));
      });
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
    window.requestAnimationFrame(() => {
      window.dispatchEvent(new Event('resize'));
    });
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
