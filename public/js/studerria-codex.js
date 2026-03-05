(() => {
  const body = document.body;
  if (!body || !body.classList.contains('page-codex-showcase')) {
    return;
  }

  const root = document.getElementById('showcaseBg');
  const particleLayer = document.getElementById('showcaseParticleLayer');
  const themeToggle = document.getElementById('showcaseThemeToggle');
  if (!root || !particleLayer || !themeToggle) {
    return;
  }

  const shapes = Array.from(root.querySelectorAll('.shape-layer'));
  const particles = Array.from(particleLayer.querySelectorAll('.bg-particle'));

  const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarsePointerQuery = window.matchMedia('(pointer: coarse)');

  let viewportWidth = window.innerWidth;
  let viewportHeight = window.innerHeight;
  let centerX = viewportWidth * 0.5;
  let centerY = viewportHeight * 0.5;

  let targetX = centerX;
  let targetY = centerY;
  let currentX = centerX;
  let currentY = centerY;

  let isReducedMotion = reducedMotionQuery.matches;
  let isCoarsePointer = coarsePointerQuery.matches;
  let interactive = !isReducedMotion && !isCoarsePointer;

  let rafId = 0;
  let running = false;
  let lastFrame = 0;

  let pointerInside = false;
  let lastMoveTime = 0;
  let stableZone = '';
  let stableZoneSince = 0;
  let focusedShape = null;

  let resizeTimer = null;

  const particleState = particles.map((el, index) => {
    const spread = (index + 1) / (particles.length + 1);
    const homeX = viewportWidth * spread;
    const homeY = viewportHeight * (0.2 + ((index % 4) * 0.2));

    el.style.opacity = '0';

    return {
      el,
      index,
      homeX,
      homeY,
      x: homeX,
      y: homeY,
      targetX: homeX,
      targetY: homeY,
      scale: 0.85,
      targetScale: 0.85,
      opacity: 0,
      targetOpacity: 0,
      angle: Math.random() * Math.PI * 2,
      rotation: Math.random() * 360,
      hueShift: (Math.random() - 0.5) * 18
    };
  });

  const shapeState = shapes.map((el, index) => {
    const depth = Number(el.dataset.depth || 0.02);
    const baseX = (index % 2 === 0 ? -1 : 1) * (20 + index * 8);
    const baseY = index < 2 ? -18 + index * 6 : 12 + index * 8;

    return {
      el,
      depth,
      baseX,
      baseY,
      x: 0,
      y: 0,
      targetX: 0,
      targetY: 0,
      scale: 1,
      targetScale: 1
    };
  });

  function applyThemeClass(themeClass) {
    body.classList.remove('theme-light', 'theme-dark');
    body.classList.add(themeClass);

    const theme = themeClass === 'theme-dark' ? 'dark' : 'light';
    body.setAttribute('data-theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
    themeToggle.textContent = themeClass === 'theme-dark' ? themeToggle.dataset.lightLabel : themeToggle.dataset.darkLabel;
  }

  function initTheme() {
    const savedTheme = localStorage.getItem('ui-theme');
    const themeClass = savedTheme === 'theme-dark' ? 'theme-dark' : 'theme-light';
    applyThemeClass(themeClass);

    themeToggle.addEventListener('click', () => {
      const next = body.classList.contains('theme-dark') ? 'theme-light' : 'theme-dark';
      applyThemeClass(next);
      localStorage.setItem('ui-theme', next);
    });
  }

  function setMotionMode() {
    isReducedMotion = reducedMotionQuery.matches;
    isCoarsePointer = coarsePointerQuery.matches;
    interactive = !isReducedMotion && !isCoarsePointer;

    body.classList.toggle('showcase-reduced-motion', !interactive);

    if (!interactive) {
      clearFocus();
      pointerInside = false;
      targetX = centerX;
      targetY = centerY;
      currentX = centerX;
      currentY = centerY;

      particleState.forEach((particle) => {
        particle.targetX = particle.homeX;
        particle.targetY = particle.homeY;
        particle.targetOpacity = 0;
        particle.opacity = 0;
      });
    }
  }

  function updateViewportMetrics() {
    viewportWidth = window.innerWidth;
    viewportHeight = window.innerHeight;
    centerX = viewportWidth * 0.5;
    centerY = viewportHeight * 0.5;

    particleState.forEach((particle, index) => {
      const spread = (index + 1) / (particleState.length + 1);
      particle.homeX = viewportWidth * spread;
      particle.homeY = viewportHeight * (0.18 + ((index % 5) * 0.16));

      if (!pointerInside || !interactive) {
        particle.x = particle.homeX;
        particle.y = particle.homeY;
        particle.targetX = particle.homeX;
        particle.targetY = particle.homeY;
      }
    });
  }

  function zoneKey(x, y) {
    const col = Math.max(0, Math.min(2, Math.floor((x / Math.max(1, viewportWidth)) * 3)));
    const row = Math.max(0, Math.min(1, Math.floor((y / Math.max(1, viewportHeight)) * 2)));
    return `${row}:${col}`;
  }

  function clearFocus() {
    if (focusedShape) {
      focusedShape.classList.remove('is-focused');
      focusedShape = null;
    }

    root.classList.remove('shape-focus-active');
    shapeState.forEach((shape) => {
      shape.targetScale = 1;
    });
  }

  function focusNearestShape(x, y) {
    let nearest = null;
    let nearestDistance = Number.POSITIVE_INFINITY;

    shapeState.forEach((shape) => {
      const rect = shape.el.getBoundingClientRect();
      const dx = x - (rect.left + rect.width * 0.5);
      const dy = y - (rect.top + rect.height * 0.5);
      const distance = dx * dx + dy * dy;

      if (distance < nearestDistance) {
        nearestDistance = distance;
        nearest = shape;
      }
    });

    if (!nearest) {
      return;
    }

    root.classList.add('shape-focus-active');

    shapeState.forEach((shape) => {
      shape.targetScale = shape === nearest ? 1.14 : 0.92;
      shape.el.classList.toggle('is-focused', shape === nearest);
    });

    focusedShape = nearest.el;
  }

  function onPointerMove(event) {
    if (!interactive) {
      return;
    }

    pointerInside = true;

    targetX = event.clientX;
    targetY = event.clientY;

    const now = performance.now();
    lastMoveTime = now;

    const nextZone = zoneKey(event.clientX, event.clientY);
    if (nextZone !== stableZone) {
      stableZone = nextZone;
      stableZoneSince = now;
      clearFocus();
    }

    const heading = Math.atan2(event.clientY - centerY, event.clientX - centerX);

    particleState.forEach((particle, index) => {
      const ring = 22 + index * 1.9;
      const localAngle = heading + index * 0.48;
      particle.targetX = event.clientX + Math.cos(localAngle) * ring;
      particle.targetY = event.clientY + Math.sin(localAngle) * ring;
      particle.targetScale = 0.84 + ((index % 5) * 0.08);
      particle.targetOpacity = 0.2 + ((index % 4) * 0.17);
    });
  }

  function onPointerLeave() {
    pointerInside = false;
    targetX = centerX;
    targetY = centerY;
    stableZone = '';
    stableZoneSince = 0;
    clearFocus();

    particleState.forEach((particle) => {
      particle.targetX = particle.homeX;
      particle.targetY = particle.homeY;
      particle.targetScale = 0.82;
      particle.targetOpacity = 0;
    });
  }

  function onResize() {
    if (resizeTimer) {
      return;
    }

    resizeTimer = window.setTimeout(() => {
      resizeTimer = null;
      updateViewportMetrics();
    }, 120);
  }

  function updateShapes() {
    const normX = (currentX - centerX) / Math.max(1, viewportWidth);
    const normY = (currentY - centerY) / Math.max(1, viewportHeight);

    shapeState.forEach((shape, index) => {
      shape.targetX = normX * viewportWidth * shape.depth;
      shape.targetY = normY * viewportHeight * shape.depth;

      shape.x += (shape.targetX - shape.x) * 0.08;
      shape.y += (shape.targetY - shape.y) * 0.08;
      shape.scale += (shape.targetScale - shape.scale) * 0.08;

      const sway = Math.sin((performance.now() * 0.00008) + index) * 2.4;
      shape.el.style.transform = `translate3d(${(shape.baseX + shape.x).toFixed(2)}px, ${(shape.baseY + shape.y).toFixed(2)}px, 0) scale(${shape.scale.toFixed(3)}) rotate(${sway.toFixed(2)}deg)`;
    });
  }

  function updateParticles(now) {
    const idle = now - lastMoveTime;
    const returnHome = idle > 420 || !pointerInside;

    particleState.forEach((particle, index) => {
      if (returnHome) {
        particle.targetX = particle.homeX;
        particle.targetY = particle.homeY;
        particle.targetScale = 0.78;
        particle.targetOpacity = 0;
      }

      particle.x += (particle.targetX - particle.x) * 0.07;
      particle.y += (particle.targetY - particle.y) * 0.07;
      particle.scale += (particle.targetScale - particle.scale) * 0.09;
      particle.opacity += (particle.targetOpacity - particle.opacity) * 0.1;

      particle.rotation += 0.35 + index * 0.04;
      particle.angle += 0.008 + index * 0.0009;

      const twinkle = 0.92 + Math.sin(now * 0.0022 + particle.angle) * 0.12;
      const lightness = 58 + Math.sin(now * 0.0016 + index) * 16;
      const hue = 212 + particle.hueShift + Math.sin(now * 0.0012 + index) * 18;

      particle.el.style.opacity = particle.opacity.toFixed(3);
      particle.el.style.transform = `translate3d(${particle.x.toFixed(2)}px, ${particle.y.toFixed(2)}px, 0) translate(-50%, -50%) scale(${(particle.scale * twinkle).toFixed(3)}) rotate(${particle.rotation.toFixed(2)}deg)`;
      particle.el.style.background = `radial-gradient(circle, hsl(${hue.toFixed(1)} ${interactive ? '90%' : '62%'} ${lightness.toFixed(1)}%), transparent 72%)`;
    });
  }

  function frame(now) {
    if (!running) {
      return;
    }

    if (!lastFrame) {
      lastFrame = now;
    }

    lastFrame = now;

    if (interactive) {
      currentX += (targetX - currentX) * 0.085;
      currentY += (targetY - currentY) * 0.085;

      const isStable = pointerInside && stableZone && now - stableZoneSince > 700;
      if (isStable) {
        focusNearestShape(currentX, currentY);
      } else if (!pointerInside || now - lastMoveTime > 1900) {
        clearFocus();
      }
    } else {
      currentX = centerX;
      currentY = centerY;
    }

    updateShapes();
    updateParticles(now);

    rafId = window.requestAnimationFrame(frame);
  }

  function start() {
    if (running) {
      return;
    }
    running = true;
    lastFrame = 0;
    rafId = window.requestAnimationFrame(frame);
  }

  function stop() {
    running = false;
    if (rafId) {
      window.cancelAnimationFrame(rafId);
      rafId = 0;
    }
  }

  function onVisibilityChange() {
    if (document.hidden) {
      stop();
      return;
    }

    if (!running) {
      start();
    }
  }

  initTheme();
  updateViewportMetrics();
  setMotionMode();

  document.addEventListener('pointermove', onPointerMove, { passive: true });
  document.addEventListener('pointerleave', onPointerLeave, { passive: true });
  window.addEventListener('blur', onPointerLeave, { passive: true });
  window.addEventListener('resize', onResize, { passive: true });
  document.addEventListener('visibilitychange', onVisibilityChange);

  if (typeof reducedMotionQuery.addEventListener === 'function') {
    reducedMotionQuery.addEventListener('change', setMotionMode);
    coarsePointerQuery.addEventListener('change', setMotionMode);
  } else if (typeof reducedMotionQuery.addListener === 'function') {
    reducedMotionQuery.addListener(setMotionMode);
    coarsePointerQuery.addListener(setMotionMode);
  }

  start();
})();
