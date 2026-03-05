(() => {
  const body = document.body;
  if (!body || !body.classList.contains('page-schedule')) {
    return;
  }

  const root = document.getElementById('schedule-bg');
  if (!root) {
    return;
  }

  const blobs = Array.from(root.querySelectorAll('.blob'));
  const trailHost = document.getElementById('scheduleMouseTrail');
  if (!trailHost || blobs.length === 0) {
    return;
  }

  body.classList.add('schedule-bg-ready');

  const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarsePointerQuery = window.matchMedia('(pointer: coarse)');

  let isReduced = reducedMotionQuery.matches;
  let isCoarse = coarsePointerQuery.matches;
  let interactive = !isReduced && !isCoarse;

  let viewportWidth = window.innerWidth;
  let viewportHeight = window.innerHeight;
  let centerX = viewportWidth / 2;
  let centerY = viewportHeight / 2;

  let targetX = centerX;
  let targetY = centerY;
  let currentX = centerX;
  let currentY = centerY;
  let pointerActive = false;

  let focusedBlob = null;
  let lastPointerTime = 0;
  let lastParticleSpawn = 0;

  const pointerLerp = 0.09;
  const focusIdleMs = 3000;
  const particleSpawnIntervalMs = 34;
  const maxParticles = 16;
  const particleShapes = ['shape-circle', 'shape-cross', 'shape-star'];

  const particles = [];
  let particleIndex = 0;

  let rafId = 0;
  let running = false;
  let lastFrameTime = 0;

  let resizeTimer = null;

  function setStateClasses() {
    body.classList.toggle('schedule-bg-reduced', isReduced);
    body.classList.toggle('schedule-bg-coarse', !isReduced && isCoarse);
  }

  function updateViewportMetrics() {
    viewportWidth = window.innerWidth;
    viewportHeight = window.innerHeight;
    centerX = viewportWidth / 2;
    centerY = viewportHeight / 2;
  }

  function clearFocus() {
    if (focusedBlob) {
      focusedBlob.classList.remove('focus');
      focusedBlob = null;
    }
  }

  function resetBlobTransforms() {
    blobs.forEach((blob) => {
      blob.style.setProperty('--parallax-x', '0px');
      blob.style.setProperty('--parallax-y', '0px');
    });
  }

  function buildParticlePool() {
    const fragment = document.createDocumentFragment();
    for (let i = 0; i < maxParticles; i += 1) {
      const node = document.createElement('span');
      node.className = 'trail-particle shape-circle';
      node.setAttribute('aria-hidden', 'true');
      node.style.opacity = '0';
      fragment.appendChild(node);
      particles.push({
        el: node,
        life: 0,
        ttl: 0,
        x: 0,
        y: 0,
        vx: 0,
        vy: 0,
        rotation: 0,
        spin: 0,
        scale: 1
      });
    }
    trailHost.appendChild(fragment);
  }

  function hideParticles() {
    particles.forEach((particle) => {
      particle.life = 0;
      particle.el.style.opacity = '0';
    });
  }

  function spawnParticle(x, y, mx, my, now) {
    if (!interactive || now - lastParticleSpawn < particleSpawnIntervalMs) {
      return;
    }

    lastParticleSpawn = now;

    const particle = particles[particleIndex];
    particleIndex = (particleIndex + 1) % particles.length;

    const shape = particleShapes[Math.floor(Math.random() * particleShapes.length)];
    const size = 7 + Math.random() * 7;

    particle.life = 1;
    particle.ttl = 520 + Math.random() * 420;
    particle.x = x;
    particle.y = y;
    particle.vx = mx * 0.08 + (Math.random() - 0.5) * 0.65;
    particle.vy = my * 0.08 + (Math.random() - 0.5) * 0.65;
    particle.rotation = Math.random() * 360;
    particle.spin = (Math.random() - 0.5) * 95;
    particle.scale = 0.8 + Math.random() * 0.4;

    particle.el.classList.remove('shape-circle', 'shape-cross', 'shape-star');
    particle.el.classList.add(shape);
    particle.el.style.setProperty('--particle-size', `${size.toFixed(2)}px`);
    particle.el.style.opacity = '1';
  }

  function updateParticles(deltaMs) {
    particles.forEach((particle) => {
      if (particle.life <= 0) {
        return;
      }

      particle.life -= deltaMs / particle.ttl;
      if (particle.life <= 0) {
        particle.life = 0;
        particle.el.style.opacity = '0';
        return;
      }

      const progress = 1 - particle.life;
      const opacity = 1 - progress;
      const scale = particle.scale * (1 + progress * 0.24);
      const x = particle.x + particle.vx * progress * 24;
      const y = particle.y + particle.vy * progress * 24;
      const rotation = particle.rotation + particle.spin * progress;

      particle.el.style.opacity = opacity.toFixed(3);
      particle.el.style.transform = `translate3d(${x.toFixed(2)}px, ${y.toFixed(2)}px, 0) translate(-50%, -50%) rotate(${rotation.toFixed(2)}deg) scale(${scale.toFixed(3)})`;
    });
  }

  function updateFocus(x, y) {
    let nearest = null;
    let nearestDistance = Infinity;

    blobs.forEach((blob) => {
      const rect = blob.getBoundingClientRect();
      const blobCenterX = rect.left + rect.width / 2;
      const blobCenterY = rect.top + rect.height / 2;
      const dx = x - blobCenterX;
      const dy = y - blobCenterY;
      const dist = dx * dx + dy * dy;

      if (dist < nearestDistance) {
        nearestDistance = dist;
        nearest = blob;
      }
    });

    if (nearest && focusedBlob !== nearest) {
      clearFocus();
      focusedBlob = nearest;
      focusedBlob.classList.add('focus');
    }
  }

  function setParallaxFromPointer(x, y) {
    const offsetX = x - centerX;
    const offsetY = y - centerY;

    blobs.forEach((blob) => {
      const depth = Number(blob.dataset.depth || 0.02);
      blob.style.setProperty('--parallax-x', `${(offsetX * depth).toFixed(2)}px`);
      blob.style.setProperty('--parallax-y', `${(offsetY * depth).toFixed(2)}px`);
    });
  }

  function onPointerMove(event) {
    if (!interactive) {
      return;
    }

    pointerActive = true;
    targetX = event.clientX;
    targetY = event.clientY;

    const now = performance.now();
    lastPointerTime = now;

    spawnParticle(
      event.clientX,
      event.clientY,
      Number.isFinite(event.movementX) ? event.movementX : 0,
      Number.isFinite(event.movementY) ? event.movementY : 0,
      now
    );

    updateFocus(event.clientX, event.clientY);
  }

  function onPointerLeave() {
    pointerActive = false;
    targetX = centerX;
    targetY = centerY;
  }

  function applyMode() {
    isReduced = reducedMotionQuery.matches;
    isCoarse = coarsePointerQuery.matches;
    interactive = !isReduced && !isCoarse;

    setStateClasses();

    if (!interactive) {
      pointerActive = false;
      targetX = centerX;
      targetY = centerY;
      currentX = centerX;
      currentY = centerY;
      clearFocus();
      hideParticles();
      resetBlobTransforms();
      return;
    }

    lastPointerTime = performance.now();
  }

  function frame(timestamp) {
    if (!running) {
      return;
    }

    if (!lastFrameTime) {
      lastFrameTime = timestamp;
    }

    const deltaMs = Math.min(64, timestamp - lastFrameTime);
    lastFrameTime = timestamp;

    if (interactive) {
      currentX += (targetX - currentX) * pointerLerp;
      currentY += (targetY - currentY) * pointerLerp;
      setParallaxFromPointer(currentX, currentY);

      if (timestamp - lastPointerTime > focusIdleMs) {
        clearFocus();
      }

      updateParticles(deltaMs);
    }

    if (!pointerActive && interactive) {
      targetX = centerX;
      targetY = centerY;
    }

    rafId = window.requestAnimationFrame(frame);
  }

  function startLoop() {
    if (running) {
      return;
    }
    running = true;
    lastFrameTime = 0;
    rafId = window.requestAnimationFrame(frame);
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

  function onResize() {
    if (resizeTimer) {
      return;
    }

    resizeTimer = window.setTimeout(() => {
      resizeTimer = null;
      updateViewportMetrics();
      if (!pointerActive) {
        targetX = centerX;
        targetY = centerY;
      }
    }, 120);
  }

  buildParticlePool();
  updateViewportMetrics();
  setStateClasses();
  applyMode();

  document.addEventListener('pointermove', onPointerMove, { passive: true });
  document.addEventListener('pointerleave', onPointerLeave, { passive: true });
  window.addEventListener('blur', onPointerLeave, { passive: true });
  window.addEventListener('resize', onResize, { passive: true });
  document.addEventListener('visibilitychange', onVisibilityChange);

  if (typeof reducedMotionQuery.addEventListener === 'function') {
    reducedMotionQuery.addEventListener('change', applyMode);
    coarsePointerQuery.addEventListener('change', applyMode);
  } else if (typeof reducedMotionQuery.addListener === 'function') {
    reducedMotionQuery.addListener(applyMode);
    coarsePointerQuery.addListener(applyMode);
  }

  startLoop();
})();
