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

  const symbols = ['→', '↗', '↘', '0', '×'];
  const shapeWraps = Array.from(bgRoot.querySelectorAll('.bg-shape-wrap'));

  const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarsePointerQuery = window.matchMedia('(pointer: coarse)');

  class TrailParticle {
    constructor(host, mode, symbolsPool) {
      this.mode = mode;
      this.symbolsPool = symbolsPool;
      this.el = document.createElement('span');
      this.el.className = `trail-char ${mode}`;
      this.assignSymbol();
      host.appendChild(this.el);

      this.x = 0;
      this.y = 0;
      this.targetX = 0;
      this.targetY = 0;
      this.opacity = 0;
      this.targetOpacity = 0;
      this.scale = 0.8;
      this.targetScale = 0.8;
      this.rotation = 0;
      this.targetRotation = 0;
      this.active = mode === 'ring';
      this.originX = 0;
      this.originY = 0;
      this.vx = 0;
      this.vy = 0;
      this.spin = 0;
      this.startAt = 0;
      this.duration = 0;
      this.nextGlyphAt = 0;
      this.homeAngle = 0;
      this.homeRadius = 0;
    }

    assignSymbol() {
      const glyph = this.symbolsPool[Math.floor(Math.random() * this.symbolsPool.length)] || '0';
      this.el.textContent = glyph;
    }

    setTarget(x, y, opacity, scale, rotation) {
      this.targetX = x;
      this.targetY = y;
      this.targetOpacity = opacity;
      this.targetScale = scale;
      this.targetRotation = rotation;
    }

    spawn(x, y, now) {
      this.assignSymbol();
      this.active = true;
      this.originX = x;
      this.originY = y;
      this.vx = (Math.random() - 0.5) * 68;
      this.vy = (Math.random() - 0.5) * 68;
      this.spin = (Math.random() - 0.5) * 140;
      this.rotation = Math.random() * 360;
      this.startAt = now;
      this.duration = 320 + Math.random() * 200;
      this.scale = 0.15;
      this.opacity = 0;
    }

    hide() {
      this.active = false;
      this.opacity = 0;
      this.targetOpacity = 0;
      this.el.style.opacity = '0';
    }

    update(now) {
      if (this.mode === 'ring') {
        this.x += (this.targetX - this.x) * 0.11;
        this.y += (this.targetY - this.y) * 0.11;
        this.opacity += (this.targetOpacity - this.opacity) * 0.1;
        this.scale += (this.targetScale - this.scale) * 0.12;
        this.rotation += (this.targetRotation - this.rotation) * 0.08;
        this.apply();
        return;
      }

      if (!this.active) {
        this.el.style.opacity = '0';
        return;
      }

      const progress = (now - this.startAt) / this.duration;
      if (progress >= 1) {
        this.hide();
        return;
      }

      const eased = progress < 0.5 ? progress * 2 : (1 - progress) * 2;
      this.x = this.originX + this.vx * progress;
      this.y = this.originY + this.vy * progress;
      this.opacity = Math.max(0, eased * 0.55);
      this.scale = 0.2 + progress * 1.0;
      this.rotation += this.spin * 0.016;
      this.apply();
    }

    apply() {
      this.el.style.opacity = this.opacity.toFixed(3);
      this.el.style.transform = `translate3d(${this.x.toFixed(2)}px, ${this.y.toFixed(2)}px, 0) translate(-50%, -50%) scale(${this.scale.toFixed(3)}) rotate(${this.rotation.toFixed(2)}deg)`;
    }
  }

  const ringCount = 10;
  const burstCount = 8;

  const ringParticles = Array.from({ length: ringCount }, () => new TrailParticle(trailHost, 'ring', symbols));
  const burstParticles = Array.from({ length: burstCount }, () => new TrailParticle(trailHost, 'burst', symbols));

  const fallbackParticle = document.createElement('span');
  fallbackParticle.className = 'trail-char fallback';
  fallbackParticle.textContent = '0';
  trailHost.appendChild(fallbackParticle);

  ringParticles.forEach((particle, index) => {
    particle.homeAngle = (Math.PI * 2 * index) / ringCount;
    particle.homeRadius = 70 + (index % 3) * 12;
    particle.nextGlyphAt = performance.now() + 900 + index * 80;
  });

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

  let pointerInside = false;
  let lastMoveAt = 0;
  let lastBurstAt = 0;
  let burstCursor = 0;

  let stableZone = '';
  let stableZoneSince = 0;
  let focusedShape = null;

  let isReducedMotion = reducedMotionQuery.matches;
  let isCoarsePointer = coarsePointerQuery.matches;
  let interactive = !isReducedMotion && !isCoarsePointer;

  let resizeTimer = null;
  let rafId = 0;
  let running = false;

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
      clearFocus();

      ringParticles.forEach((particle) => {
        particle.hide();
      });
      burstParticles.forEach((particle) => {
        particle.hide();
      });

      fallbackParticle.style.opacity = '0.28';
      fallbackParticle.style.transform = `translate3d(${centerX.toFixed(2)}px, ${centerY.toFixed(2)}px, 0) translate(-50%, -50%) scale(0.86)`;
      return;
    }

    fallbackParticle.style.opacity = '0';
    lastMoveAt = performance.now();
  }

  function spawnBurst(now, x, y) {
    if (now - lastBurstAt < 56) {
      return;
    }

    lastBurstAt = now;
    const particle = burstParticles[burstCursor];
    burstCursor = (burstCursor + 1) % burstParticles.length;
    particle.spawn(x, y, now);
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
    spawnBurst(now, event.clientX, event.clientY);

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
        fallbackParticle.style.transform = `translate3d(${centerX.toFixed(2)}px, ${centerY.toFixed(2)}px, 0) translate(-50%, -50%) scale(0.86)`;
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

  function updateRingTargets(now) {
    const idleMs = now - lastMoveAt;
    const activeTrail = pointerInside && idleMs < 720;

    ringParticles.forEach((particle, index) => {
      if (now >= particle.nextGlyphAt) {
        particle.assignSymbol();
        particle.nextGlyphAt = now + 850 + Math.random() * 700;
      }

      const phase = now * 0.0011 + index * 0.62;
      let targetX;
      let targetY;
      let opacity;
      let scale;

      if (activeTrail) {
        const radius = 54 + Math.sin(now * 0.0022 + index * 0.7) * 14;
        targetX = smoothX + Math.cos(phase) * radius;
        targetY = smoothY + Math.sin(phase * 1.12) * radius * 0.74;
        opacity = 0.32 + Math.sin(now * 0.0028 + index) * 0.08;
        scale = 0.82 + Math.cos(now * 0.0022 + index) * 0.2;
      } else {
        const homePhase = particle.homeAngle + now * 0.00018;
        targetX = centerX + Math.cos(homePhase) * particle.homeRadius;
        targetY = centerY + Math.sin(homePhase * 1.07) * particle.homeRadius * 0.45;
        opacity = 0.1;
        scale = 0.74;
      }

      particle.setTarget(targetX, targetY, Math.max(0, opacity), scale, phase * 80);
      particle.update(now);
    });

    burstParticles.forEach((particle) => {
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

      updateRingTargets(now);
    } else {
      smoothX = centerX;
      smoothY = centerY;
      fallbackParticle.style.transform = `translate3d(${centerX.toFixed(2)}px, ${centerY.toFixed(2)}px, 0) translate(-50%, -50%) scale(0.86)`;
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
