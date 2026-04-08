document.addEventListener('DOMContentLoaded', () => {
  const root = document.getElementById('dynamic-bg');
  if (!root || !document.body) {
    return;
  }

  const body = document.body;
  const html = document.documentElement;
  const highlight = root.querySelector('.mouse-highlight');
  const trailHost = root.querySelector('#dynamicBgTrail');
  const parallaxLayers = Array.from(root.querySelectorAll('[data-depth]'));

  const reducedMotionMedia = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarsePointerMedia = window.matchMedia('(pointer: coarse)');
  const userAgent = String(window.navigator && window.navigator.userAgent ? window.navigator.userAgent : '');
  const vendor = String(window.navigator && window.navigator.vendor ? window.navigator.vendor : '');
  const isSafariBrowser = /Safari\//.test(userAgent)
    && !/(Chrome|Chromium|CriOS|Edg|OPR|OPT|SamsungBrowser|DuckDuckGo)/.test(userAgent)
    && /Apple/i.test(vendor || userAgent);
  const DESKTOP_ZOOM_MIN_WIDTH = 1200;

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
    { symbol: 'o', offset: 0, lane: 0, ttl: 1500, opacity: 0.34, scale: 0.88 },
    { symbol: '>', offset: 8, lane: 1, ttl: 1200, opacity: 0.27, scale: 0.82 },
    { symbol: '_', offset: 14, lane: 2, ttl: 920, opacity: 0.23, scale: 0.78 }
  ];

  const MORPH_FRAME_MS = 42;
  const TRAIL_FRAME_MS = 34;
  const MAX_TRAIL_PARTICLES = 72;

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
    rafId: 0,
    lastMorphAt: 0,
    lastTrailAt: 0
  };

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
    const shouldNeutralizeZoom = isSafariBrowser
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

  function resolveTheme() {
    if (body.classList.contains('theme-dark')) {
      return 'dark';
    }

    if (body.classList.contains('theme-light')) {
      return 'light';
    }

    const bodyTheme = body.getAttribute('data-theme');
    if (bodyTheme === 'dark' || bodyTheme === 'light') {
      return bodyTheme;
    }

    const htmlTheme = html.getAttribute('data-theme');
    if (htmlTheme === 'dark' || htmlTheme === 'light') {
      return htmlTheme;
    }

    return 'light';
  }

  function syncThemeAttribute() {
    const nextTheme = resolveTheme();
    if (html.getAttribute('data-theme') !== nextTheme) {
      html.setAttribute('data-theme', nextTheme);
    }
  }

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
      this.baseOpacity = 0.3;
    }

    spawn(config) {
      this.active = true;
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

      const progress = (now - this.birth) / this.ttl;
      if (progress >= 1) {
        this.hide();
        return;
      }

      const fade = Math.pow(1 - progress, 1.18);
      const x = this.originX + (this.driftX * progress);
      const y = this.originY + (this.driftY * progress);
      const scale = this.baseScale + (progress * 0.1);
      const rotation = this.rotation + (this.spin * progress);

      this.el.style.opacity = (this.baseOpacity * fade).toFixed(3);
      this.el.style.transform = `translate3d(${x.toFixed(2)}px, ${y.toFixed(2)}px, 0) translate(-50%, -50%) scale(${scale.toFixed(3)}) rotate(${rotation.toFixed(2)}deg)`;
    }
  }

  const trailParticles = trailHost
    ? Array.from({ length: MAX_TRAIL_PARTICLES }, () => new TrailParticle(trailHost))
    : [];
  let trailCursor = 0;

  body.classList.add('dynamic-bg-ready');
  syncThemeAttribute();

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

  function spawnTrail(now) {
    if (!trailParticles.length || state.reducedMotion || state.coarsePointer) {
      return;
    }

    if (now - state.lastTrailAt < TRAIL_FRAME_MS) {
      return;
    }

    const movementX = state.targetX - state.currentX;
    const movementY = state.targetY - state.currentY;
    const speed = Math.hypot(movementX, movementY);
    if (speed < 0.45) {
      return;
    }

    state.lastTrailAt = now;

    const angle = Math.atan2(movementY, movementX);
    const forwardX = Math.cos(angle);
    const forwardY = Math.sin(angle);
    const normalX = -forwardY;
    const normalY = forwardX;

    TRAIL_PATTERN.forEach((node) => {
      const side = node.lane === 0 ? 0 : (Math.random() < 0.5 ? -1 : 1);
      const lateral = node.lane * 4.5 * side;
      const px = state.currentX - (forwardX * node.offset) + (normalX * lateral);
      const py = state.currentY - (forwardY * node.offset) + (normalY * lateral);

      const particle = trailParticles[trailCursor];
      trailCursor = (trailCursor + 1) % trailParticles.length;

      particle.spawn({
        symbol: node.symbol,
        x: px,
        y: py,
        driftX: (forwardX * (5 + (node.lane * 2))) + ((Math.random() - 0.5) * 4),
        driftY: (forwardY * (5 + (node.lane * 2))) + ((Math.random() - 0.5) * 4),
        rotation: (Math.random() - 0.5) * 6,
        spin: (Math.random() - 0.5) * 12,
        ttl: node.ttl + Math.random() * 180,
        scale: node.scale,
        opacity: node.opacity,
        now
      });
    });
  }

  function updateTrail(now) {
    trailParticles.forEach((particle) => {
      particle.update(now);
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
      state.targetX = state.width * (0.5 + (Math.sin(wave) * 0.06));
      state.targetY = state.height * (0.5 + (Math.cos(wave * 0.84) * 0.05));
    }

    state.currentX += (state.targetX - state.currentX) * 0.09;
    state.currentY += (state.targetY - state.currentY) * 0.09;

    applyHighlight();
    applyParallax();
    updateBlobMorph(now);
    spawnTrail(now);
    updateTrail(now);

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

    const point = mapPointerToScene(event.clientX, event.clientY);
    state.targetX = point.x;
    state.targetY = point.y;
  }

  function onResize() {
    syncViewportMetrics();
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

  syncViewportMetrics();
  resetState();
  applyMotionMode();
});
