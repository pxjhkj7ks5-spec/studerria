(() => {
  if (window.__studerriaBackgroundInitialized) {
    return;
  }
  window.__studerriaBackgroundInitialized = true;

  document.addEventListener('DOMContentLoaded', () => {
    const root = document.getElementById('studerriaBg');
    if (!root || !document.body) {
      return;
    }

    const body = document.body;
    const html = document.documentElement;
    const cursorGlow = root.querySelector('.studerria-cursor-glow');
    const particleHost = root.querySelector('#studerriaBgParticles');
    const parallaxLayers = Array.from(root.querySelectorAll('[data-depth]'));
    const THEME_CONTROL_SELECTOR = '.theme-toggle, .studerria-theme-toggle, .theme-toggle-btn, [data-theme-toggle]';

    const reducedMotionMedia = window.matchMedia('(prefers-reduced-motion: reduce)');
    const coarsePointerMedia = window.matchMedia('(pointer: coarse)');
    const userAgent = String(window.navigator && window.navigator.userAgent ? window.navigator.userAgent : '');
    const vendor = String(window.navigator && window.navigator.vendor ? window.navigator.vendor : '');
    const platform = String(window.navigator && window.navigator.platform ? window.navigator.platform : '');
    const isSafariBrowser = /Safari\//.test(userAgent)
      && !/(Chrome|Chromium|CriOS|Edg|OPR|OPT|SamsungBrowser|DuckDuckGo)/.test(userAgent)
      && /Apple/i.test(vendor || userAgent);
    const isAtlasLikeAppleWebView = (() => {
      const isApplePlatform = /(Mac|iPhone|iPad|iPod)/i.test(platform) || /(Macintosh|iPhone|iPad|iPod)/i.test(userAgent);
      const isAppleEngine = /AppleWebKit/i.test(userAgent) || /Apple/i.test(vendor);
      const isExcludedBrowser = /(Chrome|Chromium|CriOS|Edg|EdgiOS|OPR|OPT|SamsungBrowser|DuckDuckGo|Firefox|FxiOS)/i.test(
        userAgent
      );
      const isAtlasToken = /(Atlas|ChatGPT)/i.test(userAgent);
      const hasSafariGlobal = typeof window.safari !== 'undefined';

      return Boolean(isAtlasToken || (isApplePlatform && isAppleEngine && !isExcludedBrowser && !hasSafariGlobal));
    })();
    const DESKTOP_ZOOM_MIN_WIDTH = 1200;

    const isAuthPage = body.classList.contains('page-auth');
    const isLowPowerPage = [
      'page-schedule',
      'page-journal',
      'page-admin',
      'page-teamwork'
    ].some((className) => body.classList.contains(className));

    if (isLowPowerPage) {
      body.classList.add('studerria-bg-low-power');
    }

    const BLOB_MORPH_SHAPES = {
      primary: [
        [300, 80, 380, 60, 460, 140, 480, 240, 500, 340, 420, 420, 320, 440, 220, 460, 140, 400, 120, 300, 100, 200, 180, 100, 300, 80],
        [300, 70, 395, 58, 490, 132, 510, 232, 530, 340, 438, 448, 330, 468, 214, 488, 118, 412, 98, 308, 80, 198, 170, 96, 300, 70],
        [300, 92, 368, 78, 444, 156, 460, 254, 476, 350, 406, 414, 312, 432, 230, 448, 162, 390, 142, 296, 126, 210, 198, 114, 300, 92]
      ],
      secondary: [
        [306, 96, 404, 84, 482, 166, 500, 258, 518, 346, 444, 436, 346, 456, 236, 478, 146, 414, 126, 314, 108, 220, 184, 108, 306, 96],
        [304, 84, 420, 72, 508, 158, 522, 258, 538, 360, 454, 462, 350, 484, 226, 502, 132, 430, 112, 320, 94, 212, 180, 98, 304, 84],
        [310, 108, 392, 96, 466, 176, 486, 266, 504, 352, 430, 420, 338, 440, 250, 458, 170, 404, 150, 312, 132, 234, 204, 122, 310, 108]
      ]
    };

    const TRAIL_PATTERN = [
      { symbol: '_', variant: 'outer', lane: -2, ttl: 1600, scale: 0.8, opacity: 0.2, forwardOffset: -1.1 },
      { symbol: '>', variant: 'mid', lane: -1, ttl: 2400, scale: 0.86, opacity: 0.28, forwardOffset: -0.45 },
      { symbol: 'o', variant: 'center', lane: 0, ttl: 3200, scale: 0.92, opacity: 0.36, forwardOffset: 0 },
      { symbol: '>', variant: 'mid', lane: 1, ttl: 2400, scale: 0.86, opacity: 0.28, forwardOffset: -0.45 },
      { symbol: '_', variant: 'outer', lane: 2, ttl: 1600, scale: 0.8, opacity: 0.2, forwardOffset: -1.1 }
    ];

    const MORPH_FRAME_MS = isLowPowerPage ? 90 : 48;
    const STAMP_INTERVAL_MS = isLowPowerPage ? 58 : 44;
    const TRAIL_GRID_SIZE = isLowPowerPage ? 14 : 12;
    const CELL_COOLDOWN_MS = isLowPowerPage ? 340 : 280;
    const CELL_MEMORY_MS = 4200;
    const PATH_STAMP_STEP = isLowPowerPage ? 9 : 8;
    const MIN_STAMP_DISTANCE = 4;
    const MAX_PARTICLES = isLowPowerPage ? 120 : 180;
    const LERP_FACTOR = isLowPowerPage ? 0.08 : 0.09;

    const state = {
      width: Math.max(window.innerWidth, 1),
      height: Math.max(window.innerHeight, 1),
      viewportLeft: 0,
      viewportTop: 0,
      inputScaleX: 1,
      inputScaleY: 1,
      targetX: Math.max(window.innerWidth, 1) / 2,
      targetY: Math.max(window.innerHeight, 1) / 2,
      currentX: Math.max(window.innerWidth, 1) / 2,
      currentY: Math.max(window.innerHeight, 1) / 2,
      reducedMotion: Boolean(reducedMotionMedia.matches),
      coarsePointer: Boolean(coarsePointerMedia.matches),
      lastMorphAt: 0,
      rafId: 0,
      themeSyncGuard: false,
      lastMoveAt: 0,
      lastStampAt: 0,
      lastStampX: Math.max(window.innerWidth, 1) / 2,
      lastStampY: Math.max(window.innerHeight, 1) / 2,
      lastPointerSampleX: Math.max(window.innerWidth, 1) / 2,
      lastPointerSampleY: Math.max(window.innerHeight, 1) / 2,
      hasPointerSample: false,
      cleanupCellsAt: 0,
      lastDirection: 0,
      resizeTimerId: 0,
    };

    const recentStampCells = new Map();

    const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

    function readBodyZoom() {
      const zoomValue = Number.parseFloat(window.getComputedStyle(body).zoom || '1');
      return Number.isFinite(zoomValue) && zoomValue > 0 ? zoomValue : 1;
    }

    function readRootRenderScale() {
      const probe = document.createElement('div');
      probe.style.position = 'absolute';
      probe.style.left = '0';
      probe.style.top = '0';
      probe.style.width = '100px';
      probe.style.height = '100px';
      probe.style.visibility = 'hidden';
      probe.style.pointerEvents = 'none';
      root.appendChild(probe);
      const probeRect = probe.getBoundingClientRect();
      probe.remove();

      return {
        scaleX: Math.max((Number(probeRect.width) || 100) / 100, 0.0001),
        scaleY: Math.max((Number(probeRect.height) || 100) / 100, 0.0001),
      };
    }

    function syncViewportMetrics() {
      root.style.transformOrigin = 'top left';
      root.style.transform = 'translateZ(0)';
      root.style.zoom = '1';

      const bodyZoom = readBodyZoom();
      const shouldNeutralizeZoom = (isSafariBrowser || isAtlasLikeAppleWebView)
        && body.classList.contains('studerria-theme')
        && window.innerWidth >= DESKTOP_ZOOM_MIN_WIDTH
        && Math.abs(bodyZoom - 1) > 0.001;

      if (shouldNeutralizeZoom) {
        root.style.zoom = (1 / bodyZoom).toFixed(6);
      }

      const rect = root.getBoundingClientRect();
      const renderedWidth = Math.max(Number(rect.width) || window.innerWidth || 1, 1);
      const renderedHeight = Math.max(Number(rect.height) || window.innerHeight || 1, 1);
      const renderScale = readRootRenderScale();

      state.width = renderedWidth / renderScale.scaleX;
      state.height = renderedHeight / renderScale.scaleY;
      state.viewportLeft = Number.isFinite(rect.left) ? rect.left : 0;
      state.viewportTop = Number.isFinite(rect.top) ? rect.top : 0;
      state.inputScaleX = 1 / renderScale.scaleX;
      state.inputScaleY = 1 / renderScale.scaleY;
    }

    function mapPointerToScene(clientX, clientY) {
      return {
        x: clamp((Number(clientX || 0) - state.viewportLeft) * state.inputScaleX, 0, state.width),
        y: clamp((Number(clientY || 0) - state.viewportTop) * state.inputScaleY, 0, state.height),
      };
    }

    function toBlobPath(values) {
      return `M${values[0].toFixed(2)} ${values[1].toFixed(2)} C${values[2].toFixed(2)} ${values[3].toFixed(2)} ${values[4].toFixed(2)} ${values[5].toFixed(2)} ${values[6].toFixed(2)} ${values[7].toFixed(2)} C${values[8].toFixed(2)} ${values[9].toFixed(2)} ${values[10].toFixed(2)} ${values[11].toFixed(2)} ${values[12].toFixed(2)} ${values[13].toFixed(2)} C${values[14].toFixed(2)} ${values[15].toFixed(2)} ${values[16].toFixed(2)} ${values[17].toFixed(2)} ${values[18].toFixed(2)} ${values[19].toFixed(2)} C${values[20].toFixed(2)} ${values[21].toFixed(2)} ${values[22].toFixed(2)} ${values[23].toFixed(2)} ${values[24].toFixed(2)} ${values[25].toFixed(2)} Z`;
    }

    function smoothstep(value) {
      return value * value * (3 - (2 * value));
    }

    function toGrid(value) {
      return Math.round(value / TRAIL_GRID_SIZE) * TRAIL_GRID_SIZE;
    }

    function cellKey(x, y) {
      return `${Math.round(x / TRAIL_GRID_SIZE)}:${Math.round(y / TRAIL_GRID_SIZE)}`;
    }

    function normalizeThemeValue(rawValue) {
      const value = String(rawValue || '').trim().toLowerCase();
      if (value === 'dark' || value === 'theme-dark') return 'dark';
      if (value === 'light' || value === 'theme-light') return 'light';
      return '';
    }

    function readStoredTheme() {
      try {
        return normalizeThemeValue(localStorage.getItem('ui-theme'));
      } catch (_error) {
        return '';
      }
    }

    function writeStoredTheme(theme) {
      try {
        localStorage.setItem('ui-theme', theme === 'dark' ? 'theme-dark' : 'theme-light');
      } catch (_error) {
        // Ignore storage failures.
      }
    }

    function resolveTheme() {
      if (body.classList.contains('theme-dark') || body.classList.contains('dark')) return 'dark';
      if (body.classList.contains('theme-light') || body.classList.contains('light')) return 'light';
      const bodyTheme = body.getAttribute('data-theme');
      if (bodyTheme === 'dark' || bodyTheme === 'light') return bodyTheme;
      const htmlTheme = html.getAttribute('data-theme');
      if (htmlTheme === 'dark' || htmlTheme === 'light') return htmlTheme;

      const stored = readStoredTheme();
      if (stored) return stored;
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    function applyTheme(theme, setClasses = false, persist = false) {
      const next = theme === 'dark' ? 'dark' : 'light';
      const nextClass = next === 'dark' ? 'theme-dark' : 'theme-light';
      state.themeSyncGuard = true;

      if (html.getAttribute('data-theme') !== next) {
        html.setAttribute('data-theme', next);
      }
      if (body.getAttribute('data-theme') !== next) {
        body.setAttribute('data-theme', next);
      }

      if (
        setClasses
        || !body.classList.contains(nextClass)
        || body.classList.contains('dark')
        || body.classList.contains('light')
      ) {
        body.classList.remove('theme-dark', 'theme-light', 'dark', 'light');
        body.classList.add(nextClass);
      }

      if (persist) {
        writeStoredTheme(next);
      }

      state.themeSyncGuard = false;
      return next;
    }

    function getThemeControls() {
      return Array.from(document.querySelectorAll(THEME_CONTROL_SELECTOR));
    }

    function getThemeToggleLabel(control, theme) {
      if (control.dataset.navAction === 'theme-toggle') {
        return theme === 'dark' ? 'Світла' : 'Темна';
      }
      const fallbackLight = control.classList.contains('studerria-theme-toggle') ? 'Light' : '☀️';
      const fallbackDark = control.classList.contains('studerria-theme-toggle') ? 'Dark' : '🌙';
      return theme === 'dark'
        ? (control.dataset.lightLabel || fallbackLight)
        : (control.dataset.darkLabel || fallbackDark);
    }

    function updateToggleLabel() {
      const theme = resolveTheme();
      getThemeControls().forEach((control) => {
        if (!(control instanceof HTMLElement)) return;
        control.textContent = getThemeToggleLabel(control, theme);
      });
    }

    function initThemeToggle() {
      updateToggleLabel();
      document.addEventListener('click', (event) => {
        const control = event.target instanceof Element
          ? event.target.closest(THEME_CONTROL_SELECTOR)
          : null;
        if (!(control instanceof HTMLElement)) {
          return;
        }

        event.preventDefault();
        event.stopImmediatePropagation();

        const current = resolveTheme();
        const next = current === 'dark' ? 'light' : 'dark';
        applyTheme(next, true, true);
        updateToggleLabel();
      }, true);
    }

    const morphStates = Array.from(root.querySelectorAll('[data-blob-path]')).map((pathEl, index) => {
      const kind = pathEl.dataset.blobPath === 'secondary' ? 'secondary' : 'primary';
      const frames = BLOB_MORPH_SHAPES[kind] || BLOB_MORPH_SHAPES.primary;
      pathEl.setAttribute('d', toBlobPath(frames[0]));
      return {
        pathEl,
        frames,
        duration: kind === 'secondary' ? 45000 : 30000,
        offset: index * 6200,
      };
    });

    class Particle {
      constructor(host) {
        this.el = document.createElement('span');
        this.el.className = 'studerria-bg-particle';
        host.appendChild(this.el);

        this.active = false;
        this.originX = 0;
        this.originY = 0;
        this.driftX = 0;
        this.driftY = 0;
        this.rotation = 0;
        this.spin = 0;
        this.birth = 0;
        this.ttl = 0;
        this.baseScale = 1;
        this.baseOpacity = 0.3;
      }

      spawn(config) {
        this.active = true;
        this.el.className = `studerria-bg-particle ${config.variant || ''}`.trim();
        this.el.textContent = config.symbol;
        this.originX = config.x;
        this.originY = config.y;
        this.driftX = config.driftX;
        this.driftY = config.driftY;
        this.rotation = config.rotation;
        this.spin = config.spin;
        this.birth = config.now;
        this.ttl = config.ttl;
        this.baseScale = config.scale;
        this.baseOpacity = config.opacity;
        this.el.style.opacity = '0';
      }

      hide() {
        this.active = false;
        this.el.style.opacity = '0';
      }

      update(now) {
        if (!this.active) return;

        const progress = (now - this.birth) / this.ttl;
        if (progress >= 1) {
          this.hide();
          return;
        }

        const fade = Math.pow(1 - progress, 1.26);
        const x = this.originX + (this.driftX * progress);
        const y = this.originY + (this.driftY * progress);
        const scale = this.baseScale + (progress * 0.05);
        const rotation = this.rotation + (this.spin * progress);

        this.el.style.opacity = (this.baseOpacity * fade).toFixed(3);
        this.el.style.transform = `translate3d(${x.toFixed(2)}px, ${y.toFixed(2)}px, 0) translate(-50%, -50%) scale(${scale.toFixed(3)}) rotate(${rotation.toFixed(2)}deg)`;
      }
    }

    const particles = particleHost
      ? Array.from({ length: MAX_PARTICLES }, () => new Particle(particleHost))
      : [];
    let particleCursor = 0;

    function hideParticles() {
      particles.forEach((particle) => particle.hide());
    }

    function applyCursorGlow() {
      if (!cursorGlow) return;
      cursorGlow.style.left = `${state.currentX.toFixed(2)}px`;
      cursorGlow.style.top = `${state.currentY.toFixed(2)}px`;
      cursorGlow.style.transform = 'translate3d(-50%, -50%, 0)';
    }

    function applyParallax() {
      parallaxLayers.forEach((layer) => {
        layer.style.transform = 'translate3d(0px, 0px, 0)';
      });
    }

    function updateMorph(now) {
      if (state.reducedMotion || now - state.lastMorphAt < MORPH_FRAME_MS) return;
      state.lastMorphAt = now;

      morphStates.forEach((morphState) => {
        const frames = morphState.frames;
        const frameCount = frames.length;
        if (frameCount < 2) return;

        const cycle = ((now + morphState.offset) % morphState.duration) / morphState.duration;
        const progress = cycle * frameCount;
        const fromIndex = Math.floor(progress) % frameCount;
        const toIndex = (fromIndex + 1) % frameCount;
        const localT = smoothstep(progress - Math.floor(progress));

        const from = frames[fromIndex];
        const to = frames[toIndex];
        const mixed = new Array(from.length);
        for (let i = 0; i < from.length; i += 1) {
          mixed[i] = from[i] + ((to[i] - from[i]) * localT);
        }
        morphState.pathEl.setAttribute('d', toBlobPath(mixed));
      });
    }

    function cleanupRecentCells(now) {
      if (now < state.cleanupCellsAt) return;
      state.cleanupCellsAt = now + 640;
      recentStampCells.forEach((timestamp, key) => {
        if (now - timestamp > CELL_MEMORY_MS) {
          recentStampCells.delete(key);
        }
      });
    }

    function spawnBrushStamp(now, x, y, movementX, movementY) {
      if (!particles.length || state.reducedMotion || state.coarsePointer) return;

      const magnitude = Math.hypot(movementX, movementY);
      if (magnitude > 0.22) {
        state.lastDirection = Math.atan2(movementY, movementX);
      }

      const distanceFromLast = Math.hypot(x - state.lastStampX, y - state.lastStampY);
      if (distanceFromLast < MIN_STAMP_DISTANCE) {
        return;
      }

      const quantizedX = toGrid(x);
      const quantizedY = toGrid(y);
      state.lastStampX = quantizedX;
      state.lastStampY = quantizedY;

      cleanupRecentCells(now);

      const forwardX = Math.cos(state.lastDirection);
      const forwardY = Math.sin(state.lastDirection);
      const normalX = -forwardY;
      const normalY = forwardX;
      const laneStep = TRAIL_GRID_SIZE - 2;
      const thisStampCells = new Set();

      TRAIL_PATTERN.forEach((node) => {
        const rawX = quantizedX
          + (normalX * node.lane * laneStep)
          + (forwardX * node.forwardOffset * laneStep);
        const rawY = quantizedY
          + (normalY * node.lane * laneStep)
          + (forwardY * node.forwardOffset * laneStep);

        const px = toGrid(rawX);
        const py = toGrid(rawY);
        const key = cellKey(px, py);

        if (thisStampCells.has(key)) {
          return;
        }

        const lastCellTime = recentStampCells.get(key) || 0;
        if (now - lastCellTime < CELL_COOLDOWN_MS) {
          return;
        }

        thisStampCells.add(key);
        recentStampCells.set(key, now);

        const particle = particles[particleCursor];
        particleCursor = (particleCursor + 1) % particles.length;

        particle.spawn({
          variant: node.variant,
          symbol: node.symbol,
          x: px,
          y: py,
          driftX: forwardX * 0.06,
          driftY: forwardY * 0.06,
          rotation: (Math.random() - 0.5) * 1.2,
          spin: (Math.random() - 0.5) * 1.8,
          ttl: node.ttl,
          scale: node.scale,
          opacity: node.opacity,
          now,
        });
      });

      state.lastStampAt = now;
    }

    function spawnTrail(now, x, y) {
      if (state.reducedMotion || state.coarsePointer || !particles.length) {
        return;
      }

      if (!state.hasPointerSample) {
        state.lastPointerSampleX = x;
        state.lastPointerSampleY = y;
        state.lastStampX = x;
        state.lastStampY = y;
        state.hasPointerSample = true;
        return;
      }

      const dx = x - state.lastPointerSampleX;
      const dy = y - state.lastPointerSampleY;
      const distance = Math.hypot(dx, dy);

      if (distance <= 0.01) {
        if (now - state.lastStampAt >= STAMP_INTERVAL_MS) {
          spawnBrushStamp(now, x, y, 0, 0);
        }
        return;
      }

      const steps = Math.min(32, Math.max(1, Math.ceil(distance / PATH_STAMP_STEP)));
      for (let i = 1; i <= steps; i += 1) {
        const t = i / steps;
        const sampleX = state.lastPointerSampleX + (dx * t);
        const sampleY = state.lastPointerSampleY + (dy * t);
        spawnBrushStamp(now + i, sampleX, sampleY, dx, dy);
      }

      state.lastPointerSampleX = x;
      state.lastPointerSampleY = y;
    }

    function updateParticles(now) {
      particles.forEach((particle) => particle.update(now));
    }

    function resetState() {
      state.targetX = state.width / 2;
      state.targetY = state.height / 2;
      state.currentX = state.targetX;
      state.currentY = state.targetY;
      state.lastStampX = state.targetX;
      state.lastStampY = state.targetY;
      state.lastPointerSampleX = state.targetX;
      state.lastPointerSampleY = state.targetY;
      state.hasPointerSample = false;
      applyCursorGlow();
      applyParallax();
    }

    function tick(now) {
      if (state.reducedMotion || document.hidden) {
        state.rafId = 0;
        return;
      }

      if (state.coarsePointer) {
        const wave = now * 0.00024;
        state.targetX = state.width * (0.5 + (Math.sin(wave) * 0.05));
        state.targetY = state.height * (0.5 + (Math.cos(wave * 0.82) * 0.04));
      }

      state.currentX += (state.targetX - state.currentX) * LERP_FACTOR;
      state.currentY += (state.targetY - state.currentY) * LERP_FACTOR;

      applyCursorGlow();
      applyParallax();
      updateMorph(now);
      updateParticles(now);

      state.rafId = window.requestAnimationFrame(tick);
    }

    function startLoop() {
      if (state.reducedMotion || state.rafId || document.hidden) return;
      state.rafId = window.requestAnimationFrame(tick);
    }

    function stopLoop() {
      if (!state.rafId) return;
      window.cancelAnimationFrame(state.rafId);
      state.rafId = 0;
    }

    function applyMotionMode() {
      body.classList.toggle('studerria-bg-reduced', state.reducedMotion);
      body.classList.toggle('studerria-bg-coarse', state.coarsePointer);
      if (state.reducedMotion) {
        stopLoop();
        hideParticles();
        resetState();
        recentStampCells.clear();
        return;
      }
      startLoop();
    }

    function onPointerMove(event) {
      if (state.reducedMotion || state.coarsePointer) return;
      const point = mapPointerToScene(event.clientX, event.clientY);
      const x = point.x;
      const y = point.y;
      const now = performance.now();

      state.targetX = x;
      state.targetY = y;
      state.lastMoveAt = now;

      spawnTrail(now, x, y);
    }

    function onPointerLeave() {
      state.targetX = state.width / 2;
      state.targetY = state.height / 2;
      state.hasPointerSample = false;
    }

    function onResize() {
      if (state.resizeTimerId) return;
      state.resizeTimerId = window.setTimeout(() => {
        state.resizeTimerId = 0;
        syncViewportMetrics();
        state.targetX = clamp(state.targetX, 0, state.width);
        state.targetY = clamp(state.targetY, 0, state.height);
        state.currentX = clamp(state.currentX, 0, state.width);
        state.currentY = clamp(state.currentY, 0, state.height);
      }, 140);
    }

    function onVisibilityChange() {
      if (document.hidden) {
        stopLoop();
      } else {
        startLoop();
      }
    }

    function onReducedMotionChange(event) {
      state.reducedMotion = Boolean(event.matches);
      applyMotionMode();
    }

    function onCoarsePointerChange(event) {
      state.coarsePointer = Boolean(event.matches);
      applyMotionMode();
    }

    if (typeof reducedMotionMedia.addEventListener === 'function') {
      reducedMotionMedia.addEventListener('change', onReducedMotionChange);
    } else if (typeof reducedMotionMedia.addListener === 'function') {
      reducedMotionMedia.addListener(onReducedMotionChange);
    }

    if (typeof coarsePointerMedia.addEventListener === 'function') {
      coarsePointerMedia.addEventListener('change', onCoarsePointerChange);
    } else if (typeof coarsePointerMedia.addListener === 'function') {
      coarsePointerMedia.addListener(onCoarsePointerChange);
    }

    const themeObserver = new MutationObserver(() => {
      if (state.themeSyncGuard) return;
      applyTheme(resolveTheme(), false, false);
      updateToggleLabel();
    });
    themeObserver.observe(body, { attributes: true, attributeFilter: ['class', 'data-theme'] });
    themeObserver.observe(html, { attributes: true, attributeFilter: ['class', 'data-theme'] });

    window.addEventListener('storage', (event) => {
      if (event.key !== 'ui-theme') {
        return;
      }
      const nextTheme = normalizeThemeValue(event.newValue) || resolveTheme();
      applyTheme(nextTheme, true, false);
      updateToggleLabel();
    });

    document.addEventListener('pointermove', onPointerMove, { passive: true });
    document.addEventListener('pointerleave', onPointerLeave, { passive: true });
    window.addEventListener('blur', onPointerLeave, { passive: true });
    window.addEventListener('resize', onResize, { passive: true });
    document.addEventListener('visibilitychange', onVisibilityChange, { passive: true });

    applyTheme(resolveTheme(), true, false);
    writeStoredTheme(resolveTheme());
    initThemeToggle();
    syncViewportMetrics();
    resetState();
    applyMotionMode();
  });
})();
