document.addEventListener('DOMContentLoaded', () => {
  const root = document.getElementById('dynamic-login-bg');
  if (!root || !document.body) return;

  const body = document.body;
  body.classList.add('dynamic-login-bg-ready');

  const highlight = root.querySelector('.mouse-highlight');
  const blobs = Array.from(root.querySelectorAll('.blob'));
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

  const setHighlightTransform = () => {
    if (!highlight) return;
    highlight.style.transform = `translate3d(${state.currentX.toFixed(2)}px, ${state.currentY.toFixed(2)}px, 0) translate3d(-50%, -50%, 0)`;
  };

  const setBlobParallax = () => {
    const centerX = state.width / 2;
    const centerY = state.height / 2;
    blobs.forEach((blob, index) => {
      const depth = (index + 1) * 0.02;
      const xOffset = (state.currentX - centerX) * depth;
      const yOffset = (state.currentY - centerY) * depth;
      blob.style.transform = `translate3d(${xOffset.toFixed(2)}px, ${yOffset.toFixed(2)}px, 0)`;
    });
  };

  const resetScene = () => {
    state.targetX = state.width / 2;
    state.targetY = state.height / 2;
    state.currentX = state.targetX;
    state.currentY = state.targetY;
    setHighlightTransform();
    setBlobParallax();
  };

  const loop = (timestamp) => {
    if (state.reducedMotion || document.hidden) {
      state.rafId = 0;
      return;
    }

    if (state.coarsePointer) {
      const wave = timestamp * 0.00022;
      state.targetX = state.width * (0.5 + Math.sin(wave) * 0.05);
      state.targetY = state.height * (0.5 + Math.cos(wave * 0.82) * 0.05);
    }

    state.currentX += (state.targetX - state.currentX) * 0.09;
    state.currentY += (state.targetY - state.currentY) * 0.09;

    setHighlightTransform();
    setBlobParallax();

    state.rafId = window.requestAnimationFrame(loop);
  };

  const start = () => {
    if (state.reducedMotion || state.rafId || document.hidden) return;
    state.rafId = window.requestAnimationFrame(loop);
  };

  const stop = () => {
    if (!state.rafId) return;
    window.cancelAnimationFrame(state.rafId);
    state.rafId = 0;
  };

  const applyMode = () => {
    body.classList.toggle('dynamic-login-bg-reduced', state.reducedMotion);
    body.classList.toggle('dynamic-login-bg-coarse', state.coarsePointer);
    if (state.reducedMotion) {
      stop();
      resetScene();
      return;
    }
    start();
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
    if (document.hidden) stop();
    else start();
  };

  const onReducedMotionChange = (event) => {
    state.reducedMotion = Boolean(event.matches);
    applyMode();
  };

  const onPointerTypeChange = (event) => {
    state.coarsePointer = Boolean(event.matches);
    applyMode();
  };

  if (typeof reducedMotionMedia.addEventListener === 'function') {
    reducedMotionMedia.addEventListener('change', onReducedMotionChange);
  } else if (typeof reducedMotionMedia.addListener === 'function') {
    reducedMotionMedia.addListener(onReducedMotionChange);
  }

  if (typeof coarsePointerMedia.addEventListener === 'function') {
    coarsePointerMedia.addEventListener('change', onPointerTypeChange);
  } else if (typeof coarsePointerMedia.addListener === 'function') {
    coarsePointerMedia.addListener(onPointerTypeChange);
  }

  document.addEventListener('pointermove', onPointerMove, { passive: true });
  document.addEventListener('visibilitychange', onVisibilityChange, { passive: true });
  window.addEventListener('resize', onResize, { passive: true });

  resetScene();
  applyMode();
});
