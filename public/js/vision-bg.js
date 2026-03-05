(() => {
  const body = document.body;
  if (!body || !body.classList.contains('page-vision')) {
    return;
  }

  const bgRoot = document.getElementById('visionBg');
  const trailHost = document.getElementById('visionMouseTrail');
  const themeToggle = document.getElementById('visionThemeToggle');
  if (!bgRoot || !trailHost || !themeToggle) {
    return;
  }

  const shapeWraps = Array.from(bgRoot.querySelectorAll('.bg-shape-wrap'));

  const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarsePointerQuery = window.matchMedia('(pointer: coarse)');

  const BRUSH_PATTERN = [
    { symbol: '_', variant: 'outer', lane: -2, ttl: 1400, scale: 0.8, opacity: 0.22, forwardOffset: -1.2 },
    { symbol: '>', variant: 'mid', lane: -1, ttl: 2200, scale: 0.86, opacity: 0.34, forwardOffset: -0.45 },
    { symbol: 'o', variant: 'center', lane: 0, ttl: 3000, scale: 0.92, opacity: 0.44, forwardOffset: 0 },
    { symbol: '>', variant: 'mid', lane: 1, ttl: 2200, scale: 0.86, opacity: 0.34, forwardOffset: -0.45 },
    { symbol: '_', variant: 'outer', lane: 2, ttl: 1400, scale: 0.8, opacity: 0.22, forwardOffset: -1.2 }
  ];

  const MAX_TRAIL_PARTICLES = 220;
  const STAMP_INTERVAL_MS = 96;
  const TRAIL_GRID_SIZE = 12;
  const CELL_COOLDOWN_MS = 520;
  const MIN_STAMP_DISTANCE = 10;
  const CELL_MEMORY_MS = 4200;

  class TrailParticle {
    constructor(host) {
      this.el = document.createElement('span');
      this.el.className = 'trail-char';
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
      this.baseOpacity = 0.6;
    }

    spawn(config) {
      this.active = true;
      this.el.className = `trail-char ${config.variant}`;
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
      if (!this.active) {
        return;
      }

      const life = now - this.birth;
      const progress = life / this.ttl;
      if (progress >= 1) {
        this.hide();
        return;
      }

      const fade = Math.pow(1 - progress, 1.26);
      const opacity = this.baseOpacity * fade;
      const x = this.originX + this.driftX * progress;
      const y = this.originY + this.driftY * progress;
      const scale = this.baseScale + progress * 0.05;
      const rotation = this.rotation + this.spin * progress;

      this.el.style.opacity = opacity.toFixed(3);
      this.el.style.transform = `translate3d(${x.toFixed(2)}px, ${y.toFixed(2)}px, 0) translate(-50%, -50%) scale(${scale.toFixed(3)}) rotate(${rotation.toFixed(2)}deg)`;
    }
  }

  const trailParticles = Array.from({ length: MAX_TRAIL_PARTICLES }, () => new TrailParticle(trailHost));
  let trailCursor = 0;

  const fallbackParticle = document.createElement('span');
  fallbackParticle.className = 'trail-char fallback';
  fallbackParticle.textContent = 'o';
  trailHost.appendChild(fallbackParticle);

  const shapeStates = shapeWraps.map((el) => ({
    el,
    depth: Number(el.dataset.depth || 0.02),
    x: 0,
    y: 0,
    scale: 1,
    targetScale: 1
  }));

  let viewportWidth = window.innerWidth;
  let viewportHeight = window.innerHeight;
  let centerX = viewportWidth / 2;
  let centerY = viewportHeight / 2;

  let pointerX = centerX;
  let pointerY = centerY;
  let smoothX = centerX;
  let smoothY = centerY;
  let lastDirection = 0;

  let pointerInside = false;
  let lastMoveAt = 0;
  let lastStampAt = 0;
  let lastStampX = centerX;
  let lastStampY = centerY;

  let stableZone = '';
  let stableZoneSince = 0;
  let focusedShape = null;
  let cleanupCellsAt = 0;

  let isReducedMotion = reducedMotionQuery.matches;
  let isCoarsePointer = coarsePointerQuery.matches;
  let interactive = !isReducedMotion && !isCoarsePointer;

  let resizeTimer = null;
  let rafId = 0;
  let running = false;
  const recentStampCells = new Map();

  function applyTheme(themeClass) {
    body.classList.remove('theme-light', 'theme-dark');
    body.classList.add(themeClass);

    const theme = themeClass === 'theme-dark' ? 'dark' : 'light';
    body.setAttribute('data-theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
    themeToggle.textContent = themeClass === 'theme-dark'
      ? themeToggle.dataset.lightLabel
      : themeToggle.dataset.darkLabel;
  }

  function initTheme() {
    const savedTheme = localStorage.getItem('ui-theme');
    const initial = savedTheme === 'theme-dark' ? 'theme-dark' : 'theme-light';
    applyTheme(initial);

    themeToggle.addEventListener('click', () => {
      const next = body.classList.contains('theme-dark') ? 'theme-light' : 'theme-dark';
      applyTheme(next);
      localStorage.setItem('ui-theme', next);
    });
  }

  function updateViewportMetrics() {
    viewportWidth = window.innerWidth;
    viewportHeight = window.innerHeight;
    centerX = viewportWidth / 2;
    centerY = viewportHeight / 2;

    if (!pointerInside) {
      pointerX = centerX;
      pointerY = centerY;
    }
  }

  function clearFocus() {
    if (focusedShape) {
      focusedShape.classList.remove('is-focused');
      focusedShape = null;
    }

    bgRoot.classList.remove('focus-mode');
    shapeStates.forEach((shapeState) => {
      shapeState.targetScale = 1;
      shapeState.el.classList.remove('is-focused');
    });
  }

  function focusNearestShape(x, y) {
    let nearest = null;
    let nearestDistance = Number.POSITIVE_INFINITY;

    shapeStates.forEach((shapeState) => {
      const rect = shapeState.el.getBoundingClientRect();
      const dx = x - (rect.left + rect.width / 2);
      const dy = y - (rect.top + rect.height / 2);
      const distance = dx * dx + dy * dy;
      if (distance < nearestDistance) {
        nearestDistance = distance;
        nearest = shapeState;
      }
    });

    if (!nearest) {
      return;
    }

    bgRoot.classList.add('focus-mode');
    shapeStates.forEach((shapeState) => {
      const isFocused = shapeState === nearest;
      shapeState.targetScale = isFocused ? 1.16 : 0.9;
      shapeState.el.classList.toggle('is-focused', isFocused);
    });

    focusedShape = nearest.el;
  }

  function pointerZone(x, y) {
    const column = Math.max(0, Math.min(2, Math.floor((x / Math.max(1, viewportWidth)) * 3)));
    const row = Math.max(0, Math.min(1, Math.floor((y / Math.max(1, viewportHeight)) * 2)));
    return `${row}:${column}`;
  }

  function clearTrailParticles() {
    trailParticles.forEach((particle) => {
      particle.hide();
    });
  }

  function updateMotionMode() {
    isReducedMotion = reducedMotionQuery.matches;
    isCoarsePointer = coarsePointerQuery.matches;
    interactive = !isReducedMotion && !isCoarsePointer;

    body.classList.toggle('vision-reduced-motion', !interactive);

    if (!interactive) {
      pointerInside = false;
      pointerX = centerX;
      pointerY = centerY;
      smoothX = centerX;
      smoothY = centerY;
      lastStampX = centerX;
      lastStampY = centerY;
      clearFocus();
      clearTrailParticles();
      recentStampCells.clear();

      fallbackParticle.style.opacity = '0.3';
      fallbackParticle.style.transform = `translate3d(${centerX.toFixed(2)}px, ${centerY.toFixed(2)}px, 0) translate(-50%, -50%) scale(0.88)`;
      return;
    }

    fallbackParticle.style.opacity = '0';
    lastMoveAt = performance.now();
  }

  function toGrid(value) {
    return Math.round(value / TRAIL_GRID_SIZE) * TRAIL_GRID_SIZE;
  }

  function cellKey(x, y) {
    return `${Math.round(x / TRAIL_GRID_SIZE)}:${Math.round(y / TRAIL_GRID_SIZE)}`;
  }

  function spawnBrushStamp(now, x, y, movementX, movementY) {
    const magnitude = Math.hypot(movementX, movementY);
    if (magnitude > 0.2) {
      lastDirection = Math.atan2(movementY, movementX);
    }

    const distanceFromLast = Math.hypot(x - lastStampX, y - lastStampY);
    if (distanceFromLast < MIN_STAMP_DISTANCE) {
      return;
    }

    const quantizedX = toGrid(x);
    const quantizedY = toGrid(y);
    lastStampX = quantizedX;
    lastStampY = quantizedY;

    if (now >= cleanupCellsAt) {
      cleanupCellsAt = now + 600;
      recentStampCells.forEach((timestamp, key) => {
        if (now - timestamp > CELL_MEMORY_MS) {
          recentStampCells.delete(key);
        }
      });
    }

    const forwardX = Math.cos(lastDirection);
    const forwardY = Math.sin(lastDirection);
    const normalX = -forwardY;
    const normalY = forwardX;
    const laneStep = 10;
    const thisStampCells = new Set();
    let hasSpawned = false;

    BRUSH_PATTERN.forEach((node) => {
      const rawX = quantizedX + (normalX * node.lane * laneStep) + (forwardX * node.forwardOffset * laneStep);
      const rawY = quantizedY + (normalY * node.lane * laneStep) + (forwardY * node.forwardOffset * laneStep);
      const px = toGrid(rawX);
      const py = toGrid(rawY);
      const key = cellKey(px, py);

      if (thisStampCells.has(key)) {
        return;
      }

      const lastSymbolAt = recentStampCells.get(key) || 0;
      if (now - lastSymbolAt < CELL_COOLDOWN_MS) {
        return;
      }

      thisStampCells.add(key);
      recentStampCells.set(key, now);

      const particle = trailParticles[trailCursor];
      trailCursor = (trailCursor + 1) % trailParticles.length;
      hasSpawned = true;

      particle.spawn({
        variant: node.variant,
        symbol: node.symbol,
        x: px,
        y: py,
        driftX: forwardX * 0.06,
        driftY: forwardY * 0.06,
        rotation: (Math.random() - 0.5) * 1.5,
        spin: (Math.random() - 0.5) * 2.2,
        ttl: node.ttl,
        scale: node.scale,
        opacity: node.opacity,
        now
      });
    });

    if (!hasSpawned) {
      return;
    }
  }

  function onPointerMove(event) {
    if (!interactive) {
      return;
    }

    pointerInside = true;
    pointerX = event.clientX;
    pointerY = event.clientY;

    const now = performance.now();
    lastMoveAt = now;

    if (now - lastStampAt >= STAMP_INTERVAL_MS) {
      const movementX = Number.isFinite(event.movementX) ? event.movementX : 0;
      const movementY = Number.isFinite(event.movementY) ? event.movementY : 0;
      spawnBrushStamp(now, event.clientX, event.clientY, movementX, movementY);
      lastStampAt = now;
    }

    const zone = pointerZone(event.clientX, event.clientY);
    if (zone !== stableZone) {
      stableZone = zone;
      stableZoneSince = now;
      clearFocus();
    }
  }

  function onPointerLeave() {
    pointerInside = false;
    pointerX = centerX;
    pointerY = centerY;
    stableZone = '';
    stableZoneSince = 0;
    clearFocus();
  }

  function onResize() {
    if (resizeTimer) {
      return;
    }

    resizeTimer = window.setTimeout(() => {
      resizeTimer = null;
      updateViewportMetrics();
      if (!interactive) {
        fallbackParticle.style.transform = `translate3d(${centerX.toFixed(2)}px, ${centerY.toFixed(2)}px, 0) translate(-50%, -50%) scale(0.88)`;
      }
    }, 140);
  }

  function updateShapeParallax() {
    const offsetX = (smoothX - centerX) / Math.max(1, centerX);
    const offsetY = (smoothY - centerY) / Math.max(1, centerY);

    shapeStates.forEach((shapeState) => {
      const tx = offsetX * shapeState.depth * viewportWidth;
      const ty = offsetY * shapeState.depth * viewportHeight * 0.8;

      shapeState.x += (tx - shapeState.x) * 0.09;
      shapeState.y += (ty - shapeState.y) * 0.09;
      shapeState.scale += (shapeState.targetScale - shapeState.scale) * 0.08;

      shapeState.el.style.transform = `translate3d(${shapeState.x.toFixed(2)}px, ${shapeState.y.toFixed(2)}px, 0) scale(${shapeState.scale.toFixed(3)})`;
    });
  }

  function updateTrail(now) {
    trailParticles.forEach((particle) => {
      particle.update(now);
    });
  }

  function animationFrame(now) {
    if (!running) {
      return;
    }

    if (interactive) {
      smoothX += (pointerX - smoothX) * 0.1;
      smoothY += (pointerY - smoothY) * 0.1;

      const focusReady = pointerInside && stableZone && now - stableZoneSince > 700;
      if (focusReady) {
        focusNearestShape(smoothX, smoothY);
      } else if (now - lastMoveAt > 1500) {
        clearFocus();
      }

      updateTrail(now);
    } else {
      smoothX = centerX;
      smoothY = centerY;
      fallbackParticle.style.transform = `translate3d(${centerX.toFixed(2)}px, ${centerY.toFixed(2)}px, 0) translate(-50%, -50%) scale(0.88)`;
    }

    updateShapeParallax();

    rafId = window.requestAnimationFrame(animationFrame);
  }

  function startLoop() {
    if (running) {
      return;
    }

    running = true;
    rafId = window.requestAnimationFrame(animationFrame);
  }

  function stopLoop() {
    running = false;
    if (rafId) {
      window.cancelAnimationFrame(rafId);
      rafId = 0;
    }
  }

  function onVisibilityChange() {
    if (document.hidden) {
      stopLoop();
      return;
    }

    if (!running) {
      startLoop();
    }
  }

  initTheme();
  updateViewportMetrics();
  updateMotionMode();

  document.addEventListener('pointermove', onPointerMove, { passive: true });
  document.addEventListener('pointerleave', onPointerLeave, { passive: true });
  window.addEventListener('blur', onPointerLeave, { passive: true });
  window.addEventListener('resize', onResize, { passive: true });
  document.addEventListener('visibilitychange', onVisibilityChange);

  if (typeof reducedMotionQuery.addEventListener === 'function') {
    reducedMotionQuery.addEventListener('change', updateMotionMode);
    coarsePointerQuery.addEventListener('change', updateMotionMode);
  } else if (typeof reducedMotionQuery.addListener === 'function') {
    reducedMotionQuery.addListener(updateMotionMode);
    coarsePointerQuery.addListener(updateMotionMode);
  }

  startLoop();
})();
