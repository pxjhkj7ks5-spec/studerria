document.addEventListener('DOMContentLoaded', () => {
  const root = document.getElementById('dynamic-bg');
  if (!root || !document.body) return;

  const body = document.body;
  const html = document.documentElement;
  body.classList.add('dynamic-bg-ready');

  if (
    !html.getAttribute('data-theme')
    && !body.getAttribute('data-theme')
    && !body.classList.contains('theme-dark')
    && !body.classList.contains('theme-light')
  ) {
    html.setAttribute('data-theme', 'light');
  }

  const highlight = root.querySelector('.mouse-highlight');
  const parallaxLayers = Array.from(root.querySelectorAll('[data-depth]'));
  const reducedMotionMedia = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarsePointerMedia = window.matchMedia('(pointer: coarse)');

  const state = {
    width: Math.max(window.innerWidth, 1),
    height: Math.max(window.innerHeight, 1),
    targetX: Math.max(window.innerWidth, 1) / 2,
    targetY: Math.max(window.innerHeight, 1) / 2,
    currentX: Math.max(window.innerWidth, 1) / 2,
    currentY: Math.max(window.innerHeight, 1) / 2,
    reducedMotion: Boolean(reducedMotionMedia.matches),
    coarsePointer: Boolean(coarsePointerMedia.matches),
    rafId: 0,
  };

  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

  const applyHighlight = () => {
    if (!highlight) return;
    highlight.style.transform = `translate3d(${state.currentX.toFixed(2)}px, ${state.currentY.toFixed(2)}px, 0px) translate3d(-50%, -50%, 0px)`;
  };

  const applyParallax = () => {
    const centerX = state.width / 2;
    const centerY = state.height / 2;
    parallaxLayers.forEach((layer) => {
      const depth = Number.parseFloat(layer.getAttribute('data-depth') || '0') || 0;
      const xOffset = (state.currentX - centerX) * depth;
      const yOffset = (state.currentY - centerY) * depth;
      layer.style.transform = `translate3d(${xOffset.toFixed(2)}px, ${yOffset.toFixed(2)}px, 0px)`;
    });
  };

  const resetState = () => {
    state.targetX = state.width / 2;
    state.targetY = state.height / 2;
    state.currentX = state.targetX;
    state.currentY = state.targetY;
    applyHighlight();
    applyParallax();
  };

  const tick = (timestamp) => {
    if (state.reducedMotion || document.hidden) {
      state.rafId = 0;
      return;
    }

    if (state.coarsePointer) {
      const wave = timestamp * 0.00025;
      state.targetX = state.width * (0.5 + Math.sin(wave) * 0.06);
      state.targetY = state.height * (0.5 + Math.cos(wave * 0.84) * 0.05);
    }

    state.currentX += (state.targetX - state.currentX) * 0.08;
    state.currentY += (state.targetY - state.currentY) * 0.08;

    applyHighlight();
    applyParallax();

    state.rafId = window.requestAnimationFrame(tick);
  };

  const startLoop = () => {
    if (state.reducedMotion || state.rafId || document.hidden) return;
    state.rafId = window.requestAnimationFrame(tick);
  };

  const stopLoop = () => {
    if (!state.rafId) return;
    window.cancelAnimationFrame(state.rafId);
    state.rafId = 0;
  };

  const applyMotionMode = () => {
    body.classList.toggle('dynamic-bg-reduced', state.reducedMotion);
    body.classList.toggle('dynamic-bg-coarse', state.coarsePointer);
    if (state.reducedMotion) {
      stopLoop();
      resetState();
      return;
    }
    startLoop();
  };

  const onPointerMove = (event) => {
    if (state.reducedMotion || state.coarsePointer) return;
    state.targetX = clamp(Number(event.clientX || 0), 0, state.width);
    state.targetY = clamp(Number(event.clientY || 0), 0, state.height);
  };

  const onResize = () => {
    state.width = Math.max(window.innerWidth, 1);
    state.height = Math.max(window.innerHeight, 1);
    state.targetX = clamp(state.targetX, 0, state.width);
    state.targetY = clamp(state.targetY, 0, state.height);
    state.currentX = clamp(state.currentX, 0, state.width);
    state.currentY = clamp(state.currentY, 0, state.height);
  };

  const onVisibilityChange = () => {
    if (document.hidden) {
      stopLoop();
    } else {
      startLoop();
    }
  };

  if (typeof reducedMotionMedia.addEventListener === 'function') {
    reducedMotionMedia.addEventListener('change', (event) => {
      state.reducedMotion = Boolean(event.matches);
      applyMotionMode();
    });
  } else if (typeof reducedMotionMedia.addListener === 'function') {
    reducedMotionMedia.addListener((event) => {
      state.reducedMotion = Boolean(event.matches);
      applyMotionMode();
    });
  }

  if (typeof coarsePointerMedia.addEventListener === 'function') {
    coarsePointerMedia.addEventListener('change', (event) => {
      state.coarsePointer = Boolean(event.matches);
      applyMotionMode();
    });
  } else if (typeof coarsePointerMedia.addListener === 'function') {
    coarsePointerMedia.addListener((event) => {
      state.coarsePointer = Boolean(event.matches);
      applyMotionMode();
    });
  }

  document.addEventListener('pointermove', onPointerMove, { passive: true });
  window.addEventListener('resize', onResize, { passive: true });
  document.addEventListener('visibilitychange', onVisibilityChange, { passive: true });

  resetState();
  applyMotionMode();
});
