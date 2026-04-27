(() => {
  if (window.__studerriaBackgroundInitialized) return;
  window.__studerriaBackgroundInitialized = true;

  const THEME_CONTROL_SELECTOR = '.theme-toggle, .studerria-theme-toggle, .theme-toggle-btn, [data-theme-toggle], [data-nav-action="theme-toggle"]';

  document.addEventListener('DOMContentLoaded', () => {
    const root = document.getElementById('studerriaBg');
    const body = document.body;
    const html = document.documentElement;
    if (!root || !body || !html) return;

    const cursorGlow = root.querySelector('.studerria-cursor-glow');
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    const coarsePointer = window.matchMedia('(pointer: coarse)');

    function normalizeTheme(rawValue) {
      const value = String(rawValue || '').trim().toLowerCase();
      if (value === 'dark' || value === 'theme-dark') return 'dark';
      if (value === 'light' || value === 'theme-light') return 'light';
      return '';
    }

    function storedTheme() {
      try {
        return normalizeTheme(localStorage.getItem('ui-theme'));
      } catch (_error) {
        return '';
      }
    }

    function persistTheme(theme) {
      try {
        localStorage.setItem('ui-theme', theme === 'dark' ? 'theme-dark' : 'theme-light');
      } catch (_error) {
        // Storage can be unavailable in private contexts.
      }
    }

    function resolveTheme() {
      if (body.classList.contains('theme-dark') || body.classList.contains('dark')) return 'dark';
      if (body.classList.contains('theme-light') || body.classList.contains('light')) return 'light';
      const bodyTheme = normalizeTheme(body.getAttribute('data-theme'));
      if (bodyTheme) return bodyTheme;
      const htmlTheme = normalizeTheme(html.getAttribute('data-theme'));
      if (htmlTheme) return htmlTheme;
      return storedTheme() || 'light';
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
        if (control.dataset.navAction === 'theme-toggle') {
          const label = control.querySelector('.snav-label');
          if (label) label.textContent = isDark ? 'Світла' : 'Темна';
        }
      });
    }

    function applyTheme(theme, persist = false) {
      const next = theme === 'dark' ? 'dark' : 'light';
      html.setAttribute('data-theme', next);
      body.setAttribute('data-theme', next);
      body.classList.remove('theme-light', 'theme-dark', 'light', 'dark');
      body.classList.add(next === 'dark' ? 'theme-dark' : 'theme-light');
      if (persist) persistTheme(next);
      syncThemeControls(next);
      return next;
    }

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

    if (reducedMotion.matches || coarsePointer.matches) {
      body.classList.add('studerria-motion-reduced');
      return;
    }

    let rafId = 0;
    let targetX = window.innerWidth / 2;
    let targetY = window.innerHeight / 2;
    let currentX = targetX;
    let currentY = targetY;
    let lastCanvasAt = 0;

    const canvas = document.createElement('canvas');
    canvas.className = 'studerria-codex-cursor-canvas';
    canvas.setAttribute('aria-hidden', 'true');
    root.appendChild(canvas);
    const ctx = canvas.getContext('2d', { alpha: true });
    const splats = [];
    const glyphs = ['○', '>', '_'];
    let width = 1;
    let height = 1;
    let dpr = 1;

    function resizeCanvas() {
      dpr = Math.min(2, Math.max(1, window.devicePixelRatio || 1));
      width = Math.max(window.innerWidth || 1, 1);
      height = Math.max(window.innerHeight || 1, 1);
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      if (ctx) {
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.font = '10px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
      }
    }

    function canvasColor() {
      const value = window.getComputedStyle(canvas).color;
      return value && value !== 'canvastext' ? value : 'rgba(98, 117, 255, 0.5)';
    }

    function addSplat(x, y, radius, life) {
      if (!ctx) return;
      splats.push({ x, y, radius, life, age: 0, seed: Math.random() * 1000 });
      if (splats.length > 9) splats.splice(0, splats.length - 9);
    }

    function drawCursorField() {
      if (!ctx) return;
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = canvasColor();
      ctx.font = '10px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace';

      const active = [];
      splats.forEach((splat) => {
        splat.age += 16;
        const progress = Math.min(1, splat.age / splat.life);
        const alpha = (1 - progress) * 0.62;
        if (alpha <= 0.02) return;
        active.push(splat);

        const step = 13;
        const radius = splat.radius * (0.86 + progress * 0.32);
        ctx.globalAlpha = alpha;
        for (let y = splat.y - radius; y <= splat.y + radius; y += step) {
          for (let x = splat.x - radius; x <= splat.x + radius; x += step) {
            const dx = x - splat.x;
            const dy = y - splat.y;
            const dist = Math.sqrt((dx * dx) + (dy * dy));
            if (dist > radius) continue;
            const wave = Math.sin((x + y + splat.seed) * 0.045 + progress * 4);
            if (wave < 0.24) continue;
            const index = Math.min(glyphs.length - 1, Math.floor((dist / radius) * glyphs.length));
            ctx.fillText(glyphs[index], x, y);
          }
        }
      });
      ctx.globalAlpha = 1;
      splats.splice(0, splats.length, ...active);
    }

    function tick() {
      currentX += (targetX - currentX) * 0.16;
      currentY += (targetY - currentY) * 0.16;

      if (cursorGlow) {
        cursorGlow.style.transform = `translate3d(${currentX.toFixed(1)}px, ${currentY.toFixed(1)}px, 0) translate3d(-50%, -50%, 0)`;
        cursorGlow.style.opacity = '1';
      }

      drawCursorField();
      if (Math.abs(targetX - currentX) > 0.2 || Math.abs(targetY - currentY) > 0.2 || splats.length) {
        rafId = window.requestAnimationFrame(tick);
      } else {
        rafId = 0;
      }
    }

    function ensureTick() {
      if (!rafId) rafId = window.requestAnimationFrame(tick);
    }

    document.addEventListener('pointermove', (event) => {
      targetX = event.clientX;
      targetY = event.clientY;
      const now = performance.now();
      if (now - lastCanvasAt > 46) {
        addSplat(targetX, targetY, 34, 520);
        lastCanvasAt = now;
      }
      ensureTick();
    }, { passive: true });

    document.addEventListener('pointerdown', (event) => {
      targetX = event.clientX;
      targetY = event.clientY;
      addSplat(targetX, targetY, 96, 660);
      ensureTick();
    }, { passive: true });

    document.addEventListener('pointerleave', () => {
      if (cursorGlow) cursorGlow.style.opacity = '0';
    }, { passive: true });

    window.addEventListener('resize', resizeCanvas, { passive: true });
    resizeCanvas();
  });
})();
