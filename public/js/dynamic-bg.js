(function dynamicBackgroundBoot() {
  const root = document.getElementById('dynamicBg');
  if (!root || !document.body) return;

  const body = document.body;
  body.classList.add('dynamic-bg-ready');

  const layers = Array.from(root.querySelectorAll('[data-depth]')).map((node) => ({
    node,
    depth: Number.parseFloat(node.getAttribute('data-depth') || '0') || 0,
  }));

  const reduceMotionMedia = window.matchMedia('(prefers-reduced-motion: reduce)');
  const pointerFineMedia = window.matchMedia('(hover: hover) and (pointer: fine)');

  const state = {
    width: Math.max(window.innerWidth, 1),
    height: Math.max(window.innerHeight, 1),
    targetX: 0,
    targetY: 0,
    currentX: 0,
    currentY: 0,
    targetHx: Math.max(window.innerWidth, 1) * 0.5,
    targetHy: Math.max(window.innerHeight, 1) * 0.34,
    currentHx: Math.max(window.innerWidth, 1) * 0.5,
    currentHy: Math.max(window.innerHeight, 1) * 0.34,
    reduced: Boolean(reduceMotionMedia.matches),
    safeMode: false,
    hasFinePointer: Boolean(pointerFineMedia.matches),
    frameId: 0,
    resizeScheduled: false,
  };

  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

  const syncTheme = () => {
    const explicitRaw = (body.getAttribute('data-theme') || '').trim().toLowerCase();
    const byClass = body.classList.contains('theme-light')
      ? 'light'
      : (body.classList.contains('theme-dark') ? 'dark' : '');
    const explicit = explicitRaw === 'light' || explicitRaw === 'dark' ? explicitRaw : '';
    const nextTheme = explicit
      ? explicit
      : (byClass || 'dark');
    if (body.getAttribute('data-theme') !== nextTheme) {
      body.setAttribute('data-theme', nextTheme);
    }
  };

  const applyHighlight = (x, y) => {
    const px = clamp((x / state.width) * 100, 0, 100);
    const py = clamp((y / state.height) * 100, 0, 100);
    root.style.setProperty('--dyn-hx', `${px.toFixed(2)}%`);
    root.style.setProperty('--dyn-hy', `${py.toFixed(2)}%`);
  };

  const resetStaticState = () => {
    state.targetX = 0;
    state.targetY = 0;
    state.currentX = 0;
    state.currentY = 0;
    state.targetHx = state.width * 0.5;
    state.targetHy = state.height * 0.34;
    state.currentHx = state.targetHx;
    state.currentHy = state.targetHy;
    layers.forEach(({ node }) => {
      node.style.transform = 'translate3d(0px, 0px, 0px)';
    });
    applyHighlight(state.currentHx, state.currentHy);
  };

  const onPointerMove = (event) => {
    if (state.reduced || !state.hasFinePointer) return;
    const x = Number(event.clientX || 0);
    const y = Number(event.clientY || 0);
    state.targetX = clamp(((x / state.width) - 0.5) * 2, -1, 1);
    state.targetY = clamp(((y / state.height) - 0.5) * 2, -1, 1);
    state.targetHx = clamp(x, 0, state.width);
    state.targetHy = clamp(y, 0, state.height);
  };

  const onResize = () => {
    if (state.resizeScheduled) return;
    state.resizeScheduled = true;
    window.requestAnimationFrame(() => {
      state.resizeScheduled = false;
      state.width = Math.max(window.innerWidth, 1);
      state.height = Math.max(window.innerHeight, 1);
      state.targetHx = clamp(state.targetHx, 0, state.width);
      state.targetHy = clamp(state.targetHy, 0, state.height);
      state.currentHx = clamp(state.currentHx, 0, state.width);
      state.currentHy = clamp(state.currentHy, 0, state.height);
    });
  };

  const animate = (timestamp) => {
    if (state.reduced) {
      state.frameId = 0;
      return;
    }

    if (!state.hasFinePointer) {
      const wave = timestamp * (state.safeMode ? 0.00005 : 0.00008);
      const ampX = state.safeMode ? 0.16 : 0.26;
      const ampY = state.safeMode ? 0.14 : 0.22;
      state.targetX = Math.sin(wave) * ampX;
      state.targetY = Math.cos(wave * 0.82) * ampY;
      state.targetHx = state.width * (0.5 + (Math.sin(wave * 0.9) * (state.safeMode ? 0.05 : 0.08)));
      state.targetHy = state.height * (0.36 + (Math.cos(wave * 0.74) * (state.safeMode ? 0.04 : 0.06)));
    }

    state.currentX += (state.targetX - state.currentX) * 0.075;
    state.currentY += (state.targetY - state.currentY) * 0.075;
    state.currentHx += (state.targetHx - state.currentHx) * 0.09;
    state.currentHy += (state.targetHy - state.currentHy) * 0.09;

    layers.forEach(({ node, depth }) => {
      const scale = state.safeMode ? 0.55 : 1;
      const x = state.currentX * depth * 46 * scale;
      const y = state.currentY * depth * 34 * scale;
      node.style.transform = `translate3d(${x.toFixed(2)}px, ${y.toFixed(2)}px, 0px)`;
    });
    applyHighlight(state.currentHx, state.currentHy);

    state.frameId = window.requestAnimationFrame(animate);
  };

  const startAnimation = () => {
    if (state.reduced || state.frameId) return;
    state.frameId = window.requestAnimationFrame(animate);
  };

  const stopAnimation = () => {
    if (!state.frameId) return;
    window.cancelAnimationFrame(state.frameId);
    state.frameId = 0;
  };

  const applyMotionMode = () => {
    if (state.reduced || document.hidden) {
      body.classList.add('dynamic-bg-reduced');
      stopAnimation();
      resetStaticState();
      return;
    }
    body.classList.remove('dynamic-bg-reduced');
    startAnimation();
  };

  syncTheme();
  resetStaticState();
  state.safeMode = Boolean(
    (typeof navigator !== 'undefined' && navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 4)
    || (typeof navigator !== 'undefined' && Number.isFinite(Number(navigator.deviceMemory)) && Number(navigator.deviceMemory) <= 4)
  );
  if (state.safeMode) {
    body.classList.add('dynamic-bg-safe');
  }

  const themeObserver = new MutationObserver(syncTheme);
  themeObserver.observe(body, {
    attributes: true,
    attributeFilter: ['class', 'data-theme'],
  });

  window.addEventListener('pointermove', onPointerMove, { passive: true });
  window.addEventListener('resize', onResize, { passive: true });
  document.addEventListener('visibilitychange', applyMotionMode, { passive: true });

  const onReduceMotionChange = (event) => {
    state.reduced = Boolean(event.matches);
    applyMotionMode();
  };
  const onPointerModeChange = (event) => {
    state.hasFinePointer = Boolean(event.matches);
    if (!state.hasFinePointer) {
      state.targetX = 0;
      state.targetY = 0;
    }
  };

  if (typeof reduceMotionMedia.addEventListener === 'function') {
    reduceMotionMedia.addEventListener('change', onReduceMotionChange);
  } else if (typeof reduceMotionMedia.addListener === 'function') {
    reduceMotionMedia.addListener(onReduceMotionChange);
  }

  if (typeof pointerFineMedia.addEventListener === 'function') {
    pointerFineMedia.addEventListener('change', onPointerModeChange);
  } else if (typeof pointerFineMedia.addListener === 'function') {
    pointerFineMedia.addListener(onPointerModeChange);
  }

  applyMotionMode();
})();
