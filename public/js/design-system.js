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

  function ensureAmbientLayer() {
    if (document.getElementById('studerriaBg') || document.body?.classList.contains('studerria-theme')) {
      return null;
    }
    if (!document.body) {
      return null;
    }
    let layer = document.querySelector('.ambient-layer');
    if (!layer) {
      layer = document.createElement('div');
      layer.className = 'ambient-layer';
      layer.setAttribute('aria-hidden', 'true');
      document.body.prepend(layer);
    }
    if (!layer.querySelector('.ambient-glow--a')) {
      const glowA = document.createElement('span');
      glowA.className = 'ambient-glow ambient-glow--a';
      layer.appendChild(glowA);
    }
    if (!layer.querySelector('.ambient-glow--b')) {
      const glowB = document.createElement('span');
      glowB.className = 'ambient-glow ambient-glow--b';
      layer.appendChild(glowB);
    }
    if (!layer.querySelector('.ambient-glow--c')) {
      const glowC = document.createElement('span');
      glowC.className = 'ambient-glow ambient-glow--c';
      layer.appendChild(glowC);
    }
    if (!layer.querySelector('.ambient-pointer')) {
      const pointer = document.createElement('span');
      pointer.className = 'ambient-pointer';
      layer.appendChild(pointer);
    }
    return layer;
  }

  function initAmbientMotion(layer) {
    if (!(layer instanceof HTMLElement)) {
      return;
    }
    if (layer.dataset.motionInit === '1') {
      return;
    }
    layer.dataset.motionInit = '1';

    const motionQuery = typeof window.matchMedia === 'function'
      ? window.matchMedia('(prefers-reduced-motion: reduce)')
      : null;

    let targetX = 0.5;
    let targetY = 0.36;
    let pointerX = targetX;
    let pointerY = targetY;
    let rafId = 0;
    let stopped = false;

    const clamp01 = (value) => Math.max(0, Math.min(1, value));
    const setVars = (time = Date.now()) => {
      const driftX = Math.sin(time / 3600) * 10 + Math.cos(time / 6200) * 4;
      const driftY = Math.cos(time / 4200) * 8 + Math.sin(time / 5400) * 3;
      layer.style.setProperty('--ambient-pointer-x', `${(pointerX * 100).toFixed(2)}%`);
      layer.style.setProperty('--ambient-pointer-y', `${(pointerY * 100).toFixed(2)}%`);
      layer.style.setProperty('--ambient-drift-x', `${driftX.toFixed(2)}px`);
      layer.style.setProperty('--ambient-drift-y', `${driftY.toFixed(2)}px`);
    };

    const animate = (time) => {
      rafId = 0;
      if (stopped) {
        return;
      }
      pointerX += (targetX - pointerX) * 0.075;
      pointerY += (targetY - pointerY) * 0.075;
      setVars(time);
      rafId = window.requestAnimationFrame(animate);
    };

    const schedule = () => {
      if (stopped || rafId) {
        return;
      }
      rafId = window.requestAnimationFrame(animate);
    };

    const stop = () => {
      if (!rafId) {
        return;
      }
      window.cancelAnimationFrame(rafId);
      rafId = 0;
    };

    const onPointerMove = (event) => {
      if (stopped) {
        return;
      }
      const width = Math.max(window.innerWidth || 1, 1);
      const height = Math.max(window.innerHeight || 1, 1);
      targetX = clamp01(event.clientX / width);
      targetY = clamp01(event.clientY / height);
      schedule();
    };

    const applyReducedState = (reduced) => {
      stopped = Boolean(reduced);
      if (stopped) {
        targetX = 0.5;
        targetY = 0.36;
        pointerX = targetX;
        pointerY = targetY;
        stop();
        setVars(Date.now());
        return;
      }
      schedule();
    };

    document.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('resize', schedule);

    if (motionQuery && typeof motionQuery.addEventListener === 'function') {
      motionQuery.addEventListener('change', (event) => {
        applyReducedState(event.matches);
      });
      applyReducedState(motionQuery.matches);
    } else {
      applyReducedState(false);
    }
  }

  function applyGlassDock(root) {
    const scope = root instanceof HTMLElement || root instanceof Document ? root : document;
    if (!scope.querySelectorAll) {
      return;
    }
    scope.querySelectorAll('.app-footer .footer-meta').forEach((meta) => {
      meta.classList.add('glass-dock');
    });
  }

  function applyFocusHalo(root) {
    const scope = root instanceof HTMLElement || root instanceof Document ? root : document;
    if (!scope.querySelectorAll) {
      return;
    }
    scope
      .querySelectorAll('button, a.btn, .btn-link, input, select, textarea, [role="button"], .drawer-action, .week-dot, .week-nav-btn')
      .forEach((node) => {
        if (!(node instanceof HTMLElement)) {
          return;
        }
        if (node.classList.contains('glass-tab')) {
          return;
        }
        node.classList.add('focus-halo');
      });
  }

  function initBootstrapTooltips(root) {
    if (!window.bootstrap || !window.bootstrap.Tooltip) {
      return;
    }
    const scope = root instanceof HTMLElement || root instanceof Document ? root : document;
    if (!scope.querySelectorAll) {
      return;
    }
    scope.querySelectorAll('[data-bs-toggle="tooltip"]').forEach((node) => {
      window.bootstrap.Tooltip.getOrCreateInstance(node);
    });
  }

  function initLivingSeparators() {
    const root = document.documentElement;
    if (!root || !document.querySelector('.living-separator')) {
      return;
    }

    const motionQuery = typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
    const setShift = (value) => {
      root.style.setProperty('--living-separator-shift', `${value.toFixed(2)}px`);
    };

    if (motionQuery && motionQuery.matches) {
      setShift(0);
      return;
    }

    let rafId = 0;
    const updateShift = () => {
      rafId = 0;
      const offset = window.scrollY || window.pageYOffset || 0;
      const shift = Math.sin(offset / 120) * 10;
      setShift(shift);
    };

    const scheduleUpdate = () => {
      if (rafId) {
        return;
      }
      rafId = window.requestAnimationFrame(updateShift);
    };

    updateShift();
    window.addEventListener('scroll', scheduleUpdate, { passive: true });
    window.addEventListener('resize', scheduleUpdate);

    if (motionQuery && typeof motionQuery.addEventListener === 'function') {
      motionQuery.addEventListener('change', (event) => {
        if (event.matches) {
          if (rafId) {
            window.cancelAnimationFrame(rafId);
            rafId = 0;
          }
          setShift(0);
          return;
        }
        scheduleUpdate();
      });
    }
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
          applyGlassDock(node);
          applyFocusHalo(node);
          initBootstrapTooltips(node);
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

  function applyRegisterCourseTweaks() {
    const body = document.body;
    if (!(body instanceof HTMLElement) || !body.classList.contains('page-register-course')) {
      return;
    }

    if (!document.getElementById('registerCourseTweaksStyle')) {
      const style = document.createElement('style');
      style.id = 'registerCourseTweaksStyle';
      style.textContent = `
        body.page-register-course #academicContextSummaryCard {
          border-radius: 18px;
        }
        body.theme-light.page-register-course #academicContextSummaryCard {
          background: rgba(255, 255, 255, 0.5);
          border: 1px solid rgba(148, 163, 184, 0.24);
          box-shadow: 0 12px 24px rgba(15, 23, 42, 0.08);
        }
        body.theme-dark.page-register-course #academicContextSummaryCard {
          background: linear-gradient(180deg, rgba(255, 255, 255, 0.12), rgba(255, 255, 255, 0.08));
          border: 1px solid rgba(191, 219, 254, 0.18);
          color: #f8fafc;
          box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08), 0 14px 28px rgba(5, 8, 24, 0.18);
        }
        body.theme-light.page-register-course #academicContextSummaryCard .text-muted {
          color: rgba(51, 65, 85, 0.68) !important;
        }
        body.theme-dark.page-register-course #academicContextSummaryCard .text-muted {
          color: rgba(191, 219, 254, 0.82) !important;
        }
        body.theme-light.page-register-course #academicContextSummary {
          color: #0f172a;
        }
        body.theme-dark.page-register-course #academicContextSummary {
          color: rgba(248, 250, 252, 0.96);
          text-shadow: 0 1px 0 rgba(8, 12, 28, 0.22);
        }
      `;
      document.head.appendChild(style);
    }

    const summaryValue = document.getElementById('academicContextSummary');
    const programSelect = document.getElementById('studyProgramSelect');
    const admissionInput = document.getElementById('selectedAdmissionInput');
    const campusInput = document.getElementById('selectedCampusInput');
    const trackInputs = Array.from(document.querySelectorAll('input[name="study_track"]'));
    const defaultSummary = document.documentElement.lang === 'en'
      ? 'Select track, program, admission year, and campus.'
      : 'Оберіть рівень, програму, рік вступу та кампус.';
    const trackOnlyLabels = new Set(['Bachelor', "Master's", 'Teacher', 'Бакалаврат', 'Магістратура', 'Викладач']);

    const syncSummary = () => {
      if (!(summaryValue instanceof HTMLElement)) {
        return;
      }
      const hasProgram = Boolean(programSelect && String(programSelect.value || '').trim());
      const hasAdmission = Boolean(admissionInput && String(admissionInput.value || '').trim());
      const hasCampus = Boolean(campusInput && String(campusInput.value || '').trim());
      const summaryText = normalizeText(summaryValue.textContent);
      if (!hasProgram && !hasAdmission && !hasCampus && trackOnlyLabels.has(summaryText)) {
        summaryValue.textContent = defaultSummary;
      }
    };

    trackInputs.forEach((input) => {
      input.addEventListener('change', () => window.setTimeout(syncSummary, 0));
    });
    if (programSelect instanceof HTMLElement) {
      programSelect.addEventListener('change', () => window.setTimeout(syncSummary, 0));
    }
    if (admissionInput instanceof HTMLElement) {
      admissionInput.addEventListener('change', () => window.setTimeout(syncSummary, 0));
    }
    syncSummary();
  }

  function init() {
    syncThemeAttribute();
    const ambientLayer = ensureAmbientLayer();
    if (ambientLayer) {
      initAmbientMotion(ambientLayer);
    } else {
      const staleAmbientLayer = document.querySelector('.ambient-layer');
      if (staleAmbientLayer) {
        staleAmbientLayer.remove();
      }
    }
    applySemanticBadges(document);
    applyGlassDock(document);
    applyFocusHalo(document);
    initBootstrapTooltips(document);
    initLivingSeparators();
    observeThemeChanges();
    observeDynamicBadges();
    initModalBehavior();
    applyRegisterCourseTweaks();

    document.addEventListener('focusin', (event) => {
      if (!(event.target instanceof HTMLElement)) {
        return;
      }
      if (event.target.classList.contains('focus-halo')) {
        event.target.classList.add('is-focus-halo');
      }
    });

    document.addEventListener('focusout', (event) => {
      if (!(event.target instanceof HTMLElement)) {
        return;
      }
      if (event.target.classList.contains('focus-halo')) {
        event.target.classList.remove('is-focus-halo');
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
