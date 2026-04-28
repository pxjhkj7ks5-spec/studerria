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
      return normalizeTheme(localStorage.getItem('ui-theme')) || normalizeTheme(localStorage.getItem('studerria-test-theme'));
    } catch (_error) {
      return '';
    }
  }

  function persistTheme(theme) {
    try {
      localStorage.setItem('ui-theme', theme === 'dark' ? 'theme-dark' : 'theme-light');
      localStorage.setItem('studerria-test-theme', theme);
    } catch (_error) {}
  }

  function resolveTheme() {
    const body = document.body;
    const html = document.documentElement;
    if (body && (body.classList.contains('theme-dark') || body.classList.contains('dark'))) return 'dark';
    if (body && (body.classList.contains('theme-light') || body.classList.contains('light'))) return 'light';
    const bodyTheme = body ? normalizeTheme(body.getAttribute('data-theme')) : '';
    if (bodyTheme) return bodyTheme;
    const htmlTheme = html ? normalizeTheme(html.getAttribute('data-theme')) : '';
    return htmlTheme || storedTheme() || 'light';
  }

  function syncThemeControls(theme) {
    const isDark = theme === 'dark';
    document.querySelectorAll(THEME_CONTROL_SELECTOR).forEach((control) => {
      if (!(control instanceof HTMLElement)) return;
      control.setAttribute('aria-pressed', String(isDark));
      control.setAttribute('aria-label', isDark ? 'Увімкнути світлу тему' : 'Увімкнути темну тему');
      control.querySelectorAll('[data-theme-label]').forEach((label) => {
        label.textContent = isDark ? 'Light' : 'Dark';
      });
      if (!control.querySelector('[data-theme-label], .snav-label')) {
        const nextText = isDark
          ? (control.getAttribute('data-light-label') || '')
          : (control.getAttribute('data-dark-label') || '');
        if (nextText) control.textContent = nextText;
      }
      if (control.dataset.navAction === 'theme-toggle') {
        const label = control.querySelector('.snav-label');
        if (control.dataset.staticLabel === 'true') {
          return;
        }
        const nextText = isDark
          ? (control.getAttribute('data-light-label') || '')
          : (control.getAttribute('data-dark-label') || '');
        if (label && nextText) label.textContent = nextText;
      }
    });
  }

  function applyTheme(theme, persist = false) {
    const next = theme === 'dark' ? 'dark' : 'light';
    const body = document.body;
    const html = document.documentElement;
    html.setAttribute('data-theme', next);
    if (body) {
      body.setAttribute('data-theme', next);
      body.classList.remove('theme-light', 'theme-dark', 'light', 'dark');
      body.classList.add(next === 'dark' ? 'theme-dark' : 'theme-light');
    }
    if (persist) persistTheme(next);
    syncThemeControls(next);
    return next;
  }

  function initCodexCursorLayer() {
    if (document.querySelector('[data-td-codex-cursor]')) return;

    const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const coarsePointerQuery = window.matchMedia('(pointer: coarse)');
    if (reducedMotionQuery.matches || coarsePointerQuery.matches) {
      document.body?.classList.add('studerria-motion-reduced');
      return;
    }

    const host = document.body;
    if (!host) return;

    const canvas = document.createElement('canvas');
    canvas.className = 'studerria-codex-cursor-canvas td-codex-cursor-canvas';
    canvas.setAttribute('data-td-codex-cursor', 'true');
    canvas.setAttribute('aria-hidden', 'true');
    host.prepend(canvas);

    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) {
      canvas.remove();
      return;
    }

    const charset = '○>_ ';
    const fontSize = 9;
    const gridStep = 11;
    const fpsInterval = 1000 / 30;
    let dpr = 1;
    let width = 0;
    let height = 0;
    let splats = [];
    let rafId = 0;
    let lastFrame = 0;
    let lastMoveX = window.innerWidth * 0.5;
    let lastMoveY = window.innerHeight * 0.36;
    let lastTrailAt = 0;
    let running = true;

    function resizeCanvas() {
      dpr = Math.min(2, Math.max(1, window.devicePixelRatio || 1));
      width = window.innerWidth || 1;
      height = window.innerHeight || 1;
      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.font = `${fontSize}px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
    }

    function colorFromCss() {
      const color = window.getComputedStyle(canvas).color;
      return color && color !== 'canvastext' ? color : 'rgba(120, 90, 255, 0.65)';
    }

    function addSplat(x, y, vx, vy, radius, strength, life, splash) {
      splats.push({
        x,
        y,
        vx,
        vy,
        radius,
        strength,
        life,
        age: 0,
        splash: Boolean(splash),
      });
      if (splats.length > 34) splats.splice(0, splats.length - 34);
    }

    function sampledLuma(x, y, now) {
      const nx = x / Math.max(1, width);
      const ny = y / Math.max(1, height);
      const wave = Math.sin(nx * 8.2 + now * 0.00055) * 0.16 + Math.cos((ny - nx) * 7.4 - now * 0.00042) * 0.14;
      const leftGlow = Math.exp(-(((nx - 0.12) * (nx - 0.12) / 0.026) + ((ny - 0.24) * (ny - 0.24) / 0.08))) * 0.34;
      const rightGlow = Math.exp(-(((nx - 0.84) * (nx - 0.84) / 0.045) + ((ny - 0.68) * (ny - 0.68) / 0.12))) * 0.28;
      const ribbon = Math.exp(-Math.pow((ny - 0.58) - Math.sin(nx * 4.2 + now * 0.00018) * 0.12, 2) / 0.006) * 0.22;
      return Math.max(0, Math.min(1, 0.28 + wave + leftGlow + rightGlow + ribbon));
    }

    function maskAt(x, y) {
      let value = 0;
      for (let i = 0; i < splats.length; i += 1) {
        const splat = splats[i];
        const dx = x - splat.x;
        const dy = y - splat.y;
        const dist = Math.sqrt((dx * dx) + (dy * dy));
        const fade = Math.max(0, 1 - (splat.age / splat.life));
        let local = 0;
        if (splat.splash) {
          const ringCenter = splat.radius * 0.52;
          local = Math.exp(-Math.pow((dist - ringCenter) / 100, 2));
        } else {
          local = Math.exp(-((dx * dx) + (dy * dy)) / (splat.radius * splat.radius));
        }
        value += local * fade * splat.strength;
      }
      return Math.max(0, Math.min(1, value));
    }

    function boundsForSplats() {
      if (splats.length === 0) return null;
      let minX = width;
      let minY = height;
      let maxX = 0;
      let maxY = 0;
      splats.forEach((splat) => {
        const pad = splat.radius + 60;
        minX = Math.min(minX, splat.x - pad);
        minY = Math.min(minY, splat.y - pad);
        maxX = Math.max(maxX, splat.x + pad);
        maxY = Math.max(maxY, splat.y + pad);
      });
      return {
        minX: Math.max(0, Math.floor(minX / gridStep) * gridStep),
        minY: Math.max(0, Math.floor(minY / gridStep) * gridStep),
        maxX: Math.min(width, Math.ceil(maxX / gridStep) * gridStep),
        maxY: Math.min(height, Math.ceil(maxY / gridStep) * gridStep),
      };
    }

    function draw(now) {
      ctx.clearRect(0, 0, width, height);
      const bounds = boundsForSplats();
      if (!bounds) return;

      ctx.fillStyle = colorFromCss();
      ctx.font = `${fontSize}px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace`;

      for (let y = bounds.minY; y <= bounds.maxY; y += gridStep) {
        for (let x = bounds.minX; x <= bounds.maxX; x += gridStep) {
          const density = maskAt(x, y);
          if (density < 0.045) continue;
          const luma = sampledLuma(x, y, now);
          const intensity = Math.max(0, Math.min(1, Math.pow(luma * density, 0.5) * 1.18));
          if (intensity < 0.12) continue;
          const index = intensity > 0.72 ? 0 : intensity > 0.46 ? 1 : 2;
          ctx.globalAlpha = Math.min(0.72, 0.14 + intensity * 0.58);
          ctx.fillText(charset[index], x, y);
        }
      }
      ctx.globalAlpha = 1;
    }

    function step(now) {
      if (!running) return;
      if (now - lastFrame >= fpsInterval) {
        const dt = Math.min(64, now - (lastFrame || now));
        lastFrame = now;
        splats = splats.filter((splat) => {
          splat.age += dt;
          splat.x += splat.vx * dt * 0.012;
          splat.y += splat.vy * dt * 0.012;
          splat.vx *= 0.975;
          splat.vy *= 0.975;
          return splat.age < splat.life;
        });
        draw(now);
      }
      rafId = window.requestAnimationFrame(step);
    }

    function onPointerMove(event) {
      const now = performance.now();
      const dx = event.clientX - lastMoveX;
      const dy = event.clientY - lastMoveY;
      const distance = Math.sqrt((dx * dx) + (dy * dy));
      if (distance > 7 || now - lastTrailAt > 44) {
        addSplat(event.clientX, event.clientY, dx, dy, 28, 1.25, 720, false);
        lastTrailAt = now;
      }
      lastMoveX = event.clientX;
      lastMoveY = event.clientY;
    }

    function onPointerDown(event) {
      addSplat(event.clientX, event.clientY, 0, 0, 184, 1.45, 980, true);
    }

    function teardown() {
      running = false;
      if (rafId) window.cancelAnimationFrame(rafId);
      canvas.remove();
      window.removeEventListener('resize', resizeCanvas);
      document.removeEventListener('pointermove', onPointerMove);
      document.removeEventListener('pointerdown', onPointerDown);
    }

    function onMotionModeChange() {
      if (reducedMotionQuery.matches || coarsePointerQuery.matches) teardown();
    }

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas, { passive: true });
    document.addEventListener('pointermove', onPointerMove, { passive: true });
    document.addEventListener('pointerdown', onPointerDown, { passive: true });
    if (typeof reducedMotionQuery.addEventListener === 'function') {
      reducedMotionQuery.addEventListener('change', onMotionModeChange);
      coarsePointerQuery.addEventListener('change', onMotionModeChange);
    }
    addSplat(width * 0.72, height * 0.2, 0, 0, 74, 0.32, 900, false);
    rafId = window.requestAnimationFrame(step);
  }

  document.addEventListener('DOMContentLoaded', () => {
    applyTheme(resolveTheme(), false);
    document.addEventListener('click', (event) => {
      const target = event.target instanceof Element ? event.target.closest(THEME_CONTROL_SELECTOR) : null;
      if (!(target instanceof HTMLElement)) return;
      const action = target.dataset.themeToggle || target.dataset.navAction;
      if (target.matches('[data-theme-toggle]') || action === 'theme-toggle' || target.classList.contains('theme-toggle') || target.classList.contains('theme-toggle-btn') || target.classList.contains('studerria-theme-toggle')) {
        event.preventDefault();
        applyTheme(resolveTheme() === 'dark' ? 'light' : 'dark', true);
      }
    });
    initCodexCursorLayer();
  });
})();
