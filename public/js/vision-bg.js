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

  const MAX_TRAIL_PARTICLES = 320;
  const STAMP_INTERVAL_MS = 44;
  const TRAIL_GRID_SIZE = 12;
  const CELL_COOLDOWN_MS = 320;
  const MIN_STAMP_DISTANCE = 4;
  const CELL_MEMORY_MS = 4200;
  const PATH_STAMP_STEP = 8;
  const MORPH_FRAME_MS = 42;

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

  function toBlobPath(values) {
    return `M${values[0].toFixed(2)} ${values[1].toFixed(2)} C${values[2].toFixed(2)} ${values[3].toFixed(2)} ${values[4].toFixed(2)} ${values[5].toFixed(2)} ${values[6].toFixed(2)} ${values[7].toFixed(2)} C${values[8].toFixed(2)} ${values[9].toFixed(2)} ${values[10].toFixed(2)} ${values[11].toFixed(2)} ${values[12].toFixed(2)} ${values[13].toFixed(2)} C${values[14].toFixed(2)} ${values[15].toFixed(2)} ${values[16].toFixed(2)} ${values[17].toFixed(2)} ${values[18].toFixed(2)} ${values[19].toFixed(2)} C${values[20].toFixed(2)} ${values[21].toFixed(2)} ${values[22].toFixed(2)} ${values[23].toFixed(2)} ${values[24].toFixed(2)} ${values[25].toFixed(2)} Z`;
  }

  function smoothstep(value) {
    return value * value * (3 - (2 * value));
  }

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

  const morphStates = Array.from(bgRoot.querySelectorAll('[data-blob-path]')).map((pathEl, index) => {
    const kind = pathEl.dataset.blobPath === 'secondary' ? 'secondary' : 'primary';
    const frames = BLOB_MORPH_SHAPES[kind] || BLOB_MORPH_SHAPES.primary;
    pathEl.setAttribute('d', toBlobPath(frames[0]));
    return {
      pathEl,
      frames,
      duration: kind === 'secondary' ? 45000 : 30000,
      offset: index * 6200
    };
  });

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
  let lastPointerSampleX = centerX;
  let lastPointerSampleY = centerY;
  let hasPointerSample = false;

  let stableZone = '';
  let stableZoneSince = 0;
  let focusedShape = null;
  let cleanupCellsAt = 0;
  let lastMorphAt = 0;

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
      lastPointerSampleX = centerX;
      lastPointerSampleY = centerY;
      hasPointerSample = false;
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

    if (!hasPointerSample) {
      lastPointerSampleX = event.clientX;
      lastPointerSampleY = event.clientY;
      hasPointerSample = true;
    }

    const dx = event.clientX - lastPointerSampleX;
    const dy = event.clientY - lastPointerSampleY;
    const segmentDistance = Math.hypot(dx, dy);
    const spacing = Math.max(6, PATH_STAMP_STEP);

    if (segmentDistance > 0) {
      const steps = Math.min(30, Math.max(1, Math.ceil(segmentDistance / spacing)));
      for (let i = 1; i <= steps; i += 1) {
        const t = i / steps;
        const sx = lastPointerSampleX + (dx * t);
        const sy = lastPointerSampleY + (dy * t);
        spawnBrushStamp(now + i, sx, sy, dx, dy);
      }
      lastStampAt = now;
      lastPointerSampleX = event.clientX;
      lastPointerSampleY = event.clientY;
    } else if (now - lastStampAt >= STAMP_INTERVAL_MS) {
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
    hasPointerSample = false;
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
    const offsetX = smoothX - centerX;
    const offsetY = smoothY - centerY;

    shapeStates.forEach((shapeState) => {
      const tx = offsetX * shapeState.depth;
      const ty = offsetY * shapeState.depth;

      shapeState.x += (tx - shapeState.x) * 0.09;
      shapeState.y += (ty - shapeState.y) * 0.09;
      shapeState.scale += (shapeState.targetScale - shapeState.scale) * 0.08;

      shapeState.el.style.transform = `translate3d(${shapeState.x.toFixed(2)}px, ${shapeState.y.toFixed(2)}px, 0) scale(${shapeState.scale.toFixed(3)})`;
    });
  }

  function updateBlobMorph(now) {
    if (now - lastMorphAt < MORPH_FRAME_MS) {
      return;
    }

    lastMorphAt = now;

    morphStates.forEach((state) => {
      const frames = state.frames;
      const frameCount = frames.length;
      if (frameCount < 2) {
        return;
      }

      const cycle = ((now + state.offset) % state.duration) / state.duration;
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

      state.pathEl.setAttribute('d', toBlobPath(mixed));
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

    if (!isReducedMotion) {
      updateBlobMorph(now);
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
