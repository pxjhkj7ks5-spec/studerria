document.addEventListener('DOMContentLoaded', () => {
  const root = document.getElementById('dynamic-bg');
  if (!root || !document.body) {
    return;
  }

  const body = document.body;
  const html = document.documentElement;
  const highlight = root.querySelector('.mouse-highlight');
  const parallaxLayers = Array.from(root.querySelectorAll('[data-depth]'));

  const reducedMotionMedia = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarsePointerMedia = window.matchMedia('(pointer: coarse)');

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

  const MORPH_FRAME_MS = 42;

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
    lastMorphAt: 0
  };

  const morphStates = Array.from(root.querySelectorAll('[data-blob-path]')).map((pathEl, index) => {
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

  body.classList.add('dynamic-bg-ready');

  if (!html.getAttribute('data-theme') && !body.getAttribute('data-theme')) {
    if (body.classList.contains('theme-dark')) {
      html.setAttribute('data-theme', 'dark');
    } else {
      html.setAttribute('data-theme', 'light');
    }
  }

  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));

  function toBlobPath(values) {
    return `M${values[0].toFixed(2)} ${values[1].toFixed(2)} C${values[2].toFixed(2)} ${values[3].toFixed(2)} ${values[4].toFixed(2)} ${values[5].toFixed(2)} ${values[6].toFixed(2)} ${values[7].toFixed(2)} C${values[8].toFixed(2)} ${values[9].toFixed(2)} ${values[10].toFixed(2)} ${values[11].toFixed(2)} ${values[12].toFixed(2)} ${values[13].toFixed(2)} C${values[14].toFixed(2)} ${values[15].toFixed(2)} ${values[16].toFixed(2)} ${values[17].toFixed(2)} ${values[18].toFixed(2)} ${values[19].toFixed(2)} C${values[20].toFixed(2)} ${values[21].toFixed(2)} ${values[22].toFixed(2)} ${values[23].toFixed(2)} ${values[24].toFixed(2)} ${values[25].toFixed(2)} Z`;
  }

  function smoothstep(value) {
    return value * value * (3 - (2 * value));
  }

  function syncThemeAttribute() {
    if (body.classList.contains('theme-dark')) {
      html.setAttribute('data-theme', 'dark');
      body.setAttribute('data-theme', 'dark');
      return;
    }

    if (body.classList.contains('theme-light')) {
      html.setAttribute('data-theme', 'light');
      body.setAttribute('data-theme', 'light');
    }
  }

  function applyHighlight() {
    if (!highlight) {
      return;
    }

    highlight.style.transform = `translate3d(${state.currentX.toFixed(2)}px, ${state.currentY.toFixed(2)}px, 0) translate3d(-50%, -50%, 0)`;
  }

  function applyParallax() {
    const centerX = state.width / 2;
    const centerY = state.height / 2;

    parallaxLayers.forEach((layer) => {
      const depth = Number.parseFloat(layer.getAttribute('data-depth') || '0') || 0;
      const xOffset = (state.currentX - centerX) * depth;
      const yOffset = (state.currentY - centerY) * depth;
      layer.style.transform = `translate3d(${xOffset.toFixed(2)}px, ${yOffset.toFixed(2)}px, 0)`;
    });
  }

  function updateBlobMorph(now) {
    if (state.reducedMotion || now - state.lastMorphAt < MORPH_FRAME_MS) {
      return;
    }

    state.lastMorphAt = now;

    morphStates.forEach((morphState) => {
      const frames = morphState.frames;
      const frameCount = frames.length;
      if (frameCount < 2) {
        return;
      }

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

  function resetState() {
    state.targetX = state.width / 2;
    state.targetY = state.height / 2;
    state.currentX = state.targetX;
    state.currentY = state.targetY;
    applyHighlight();
    applyParallax();
  }

  function tick(now) {
    if (state.reducedMotion || document.hidden) {
      state.rafId = 0;
      return;
    }

    if (state.coarsePointer) {
      const wave = now * 0.00025;
      state.targetX = state.width * (0.5 + Math.sin(wave) * 0.06);
      state.targetY = state.height * (0.5 + Math.cos(wave * 0.84) * 0.05);
    }

    state.currentX += (state.targetX - state.currentX) * 0.09;
    state.currentY += (state.targetY - state.currentY) * 0.09;

    applyHighlight();
    applyParallax();
    updateBlobMorph(now);

    state.rafId = window.requestAnimationFrame(tick);
  }

  function startLoop() {
    if (state.reducedMotion || state.rafId || document.hidden) {
      return;
    }

    state.rafId = window.requestAnimationFrame(tick);
  }

  function stopLoop() {
    if (!state.rafId) {
      return;
    }

    window.cancelAnimationFrame(state.rafId);
    state.rafId = 0;
  }

  function applyMotionMode() {
    body.classList.toggle('dynamic-bg-reduced', state.reducedMotion);
    body.classList.toggle('dynamic-bg-coarse', state.coarsePointer);

    if (state.reducedMotion) {
      stopLoop();
      resetState();
      return;
    }

    startLoop();
  }

  function onPointerMove(event) {
    if (state.reducedMotion || state.coarsePointer) {
      return;
    }

    state.targetX = clamp(Number(event.clientX || 0), 0, state.width);
    state.targetY = clamp(Number(event.clientY || 0), 0, state.height);
  }

  function onResize() {
    state.width = Math.max(window.innerWidth, 1);
    state.height = Math.max(window.innerHeight, 1);
    state.targetX = clamp(state.targetX, 0, state.width);
    state.targetY = clamp(state.targetY, 0, state.height);
    state.currentX = clamp(state.currentX, 0, state.width);
    state.currentY = clamp(state.currentY, 0, state.height);
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

  const themeObserver = new MutationObserver(syncThemeAttribute);
  themeObserver.observe(body, { attributes: true, attributeFilter: ['class', 'data-theme'] });

  document.addEventListener('pointermove', onPointerMove, { passive: true });
  window.addEventListener('resize', onResize, { passive: true });
  document.addEventListener('visibilitychange', onVisibilityChange, { passive: true });

  syncThemeAttribute();
  resetState();
  applyMotionMode();
});
