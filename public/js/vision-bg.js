(() => {
  const body = document.body;
  if (!body || !body.classList.contains('page-vision')) {
    return;
  }

  const bgRoot = document.getElementById('visionBg');
  const asciiCanvas = document.getElementById('visionAsciiFluid');
  const themeToggle = document.getElementById('visionThemeToggle');
  const heroElement = document.getElementById('visionHero');
  if (!bgRoot || !asciiCanvas || !themeToggle) {
    return;
  }

  const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarsePointerQuery = window.matchMedia('(pointer: coarse)');
  const safeElements = Array.from(document.querySelectorAll('[data-ascii-safe]'));

  const ASCII_CONFIG = {
    charset: '○>_ ',
    fontSize: 9,
    fps: 30,
    hoverRadiusPx: 28,
    splashRangePx: 184,
    splashThicknessPx: 100,
    maxParticles: 520,
    dprCap: 2
  };

  const asciiTrail = createAsciiTrail(asciiCanvas, heroElement, safeElements);
  let isReducedMotion = reducedMotionQuery.matches;
  let isCoarsePointer = coarsePointerQuery.matches;
  let interactive = !isReducedMotion && !isCoarsePointer;
  let rafId = 0;
  let running = false;
  let resizeTimer = null;

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function createAsciiTrail(canvas, hero, safeNodes) {
    const context = canvas.getContext('2d', { alpha: true });
    if (!context) {
      return {
        resize() {},
        refreshTheme() {},
        setInteractive() {},
        pointerMove() {},
        pointerDown() {},
        pointerUp() {},
        pointerLeave() {},
        update() {}
      };
    }

    const config = ASCII_CONFIG;
    const frameInterval = 1000 / config.fps;
    let width = 0;
    let height = 0;
    let dpr = 1;
    let enabled = false;
    let lastFrameAt = 0;
    let lastX = 0;
    let lastY = 0;
    let hasPointer = false;
    let colorRgb = '214, 220, 255';
    const particles = [];

    function getCanvasHeight() {
      if (!hero) {
        return Math.min(window.innerHeight * 1.08, 980);
      }

      const top = hero.offsetTop || 0;
      const heroHeight = hero.offsetHeight || window.innerHeight;
      return clamp(top + (heroHeight * 0.88), window.innerHeight * 0.82, 1120);
    }

    function getHeroRect() {
      if (hero) {
        const rect = hero.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) {
          return rect;
        }
      }

      return {
        left: 0,
        top: 0,
        right: window.innerWidth,
        bottom: Math.min(window.innerHeight, 920),
        width: window.innerWidth,
        height: Math.min(window.innerHeight, 920)
      };
    }

    function collectSafeRects(canvasRect) {
      return safeNodes
        .map((node) => node.getBoundingClientRect())
        .filter((rect) => rect.width > 0 && rect.height > 0)
        .map((rect) => ({
          left: rect.left - canvasRect.left,
          top: rect.top - canvasRect.top,
          right: rect.right - canvasRect.left,
          bottom: rect.bottom - canvasRect.top,
          width: rect.width,
          height: rect.height
        }));
    }

    function pointInRect(x, y, rect, padding = 0) {
      return (
        x >= rect.left - padding &&
        x <= rect.right + padding &&
        y >= rect.top - padding &&
        y <= rect.bottom + padding
      );
    }

    function isSafePoint(x, y, rects) {
      return rects.some((rect) => pointInRect(x, y, rect, rect.width > 640 ? 24 : 16));
    }

    function inHero(event) {
      const rect = getHeroRect();
      return pointInRect(event.clientX, event.clientY, rect, 64);
    }

    function localPoint(event) {
      const rect = canvas.getBoundingClientRect();
      return {
        x: event.clientX - rect.left,
        y: event.clientY - rect.top
      };
    }

    function pushParticle(x, y, intensity, radius, angleOffset = 0) {
      const character = config.charset[Math.floor(Math.random() * (config.charset.length - 1))] || '○';
      const angle = angleOffset + (Math.random() * Math.PI * 2);
      const speed = 0.18 + (Math.random() * 0.86) + (intensity * 0.42);
      const distance = Math.random() * radius;

      particles.push({
        x: x + (Math.cos(angle) * distance),
        y: y + (Math.sin(angle) * distance),
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        age: 0,
        life: 520 + (Math.random() * 620) + (intensity * 220),
        size: config.fontSize + (Math.random() * 2.4),
        alpha: clamp(0.16 + (intensity * 0.18) + (Math.random() * 0.16), 0.12, 0.48),
        char: character
      });

      if (particles.length > config.maxParticles) {
        particles.splice(0, particles.length - config.maxParticles);
      }
    }

    function seedTrail(event, amount = 10) {
      if (!enabled || !inHero(event)) {
        hasPointer = false;
        return;
      }

      const point = localPoint(event);
      if (!hasPointer) {
        lastX = point.x;
        lastY = point.y;
        hasPointer = true;
      }

      const dx = point.x - lastX;
      const dy = point.y - lastY;
      const distance = Math.hypot(dx, dy);
      const steps = clamp(Math.ceil(distance / 10), 1, 12);
      const angle = Math.atan2(dy || 0.1, dx || 0.1);

      for (let step = 1; step <= steps; step += 1) {
        const t = step / steps;
        const x = lastX + (dx * t);
        const y = lastY + (dy * t);
        for (let index = 0; index < amount; index += 1) {
          pushParticle(x, y, 0.76, config.hoverRadiusPx, angle + Math.PI);
        }
      }

      lastX = point.x;
      lastY = point.y;
    }

    function splash(event) {
      if (!enabled || !inHero(event)) {
        return;
      }

      const point = localPoint(event);
      const ringRadius = config.splashRangePx * 0.5;
      const count = 92;

      for (let index = 0; index < count; index += 1) {
        const angle = (index / count) * Math.PI * 2;
        const jitter = (Math.random() - 0.5) * config.splashThicknessPx;
        pushParticle(
          point.x + (Math.cos(angle) * (ringRadius + jitter)),
          point.y + (Math.sin(angle) * (ringRadius + jitter)),
          1.1,
          10,
          angle
        );
      }
    }

    function resize() {
      width = window.innerWidth;
      height = getCanvasHeight();
      dpr = Math.min(window.devicePixelRatio || 1, config.dprCap);

      canvas.width = Math.ceil(width * dpr);
      canvas.height = Math.ceil(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
      context.textBaseline = 'top';
      refreshTheme();
    }

    function refreshTheme() {
      const computed = window.getComputedStyle(canvas);
      colorRgb = computed.getPropertyValue('--ascii-fluid-rgb').trim() || colorRgb;
    }

    function draw(now) {
      const canvasRect = canvas.getBoundingClientRect();
      const safeRects = collectSafeRects(canvasRect);
      const themeDark = body.classList.contains('theme-dark');

      context.clearRect(0, 0, width, height);
      context.font = `${config.fontSize}px "SF Mono", "Menlo", "Consolas", monospace`;
      context.shadowColor = themeDark ? 'rgba(152, 96, 255, 0.34)' : 'rgba(102, 90, 210, 0.18)';
      context.shadowBlur = themeDark ? 8 : 2;

      for (let index = particles.length - 1; index >= 0; index -= 1) {
        const particle = particles[index];
        particle.age += now - lastFrameAt;
        particle.x += particle.vx;
        particle.y += particle.vy;
        particle.vx *= 0.978;
        particle.vy *= 0.978;

        const progress = particle.age / particle.life;
        if (progress >= 1 || particle.x < -40 || particle.x > width + 40 || particle.y < -40 || particle.y > height + 40) {
          particles.splice(index, 1);
          continue;
        }

        if (isSafePoint(particle.x, particle.y, safeRects)) {
          continue;
        }

        const fade = 1 - Math.pow(progress, 1.7);
        const drift = Math.sin((now * 0.003) + (particle.x * 0.017)) * 0.7;
        context.globalAlpha = clamp(particle.alpha * fade, 0, themeDark ? 0.5 : 0.28);
        context.font = `${particle.size.toFixed(1)}px "SF Mono", "Menlo", "Consolas", monospace`;
        context.fillStyle = `rgb(${colorRgb})`;
        context.fillText(particle.char, particle.x + drift, particle.y);
      }

      context.globalAlpha = 1;
      context.shadowBlur = 0;
    }

    function update(now) {
      if (!enabled) {
        return;
      }

      if (now - lastFrameAt < frameInterval) {
        return;
      }

      draw(now);
      lastFrameAt = now;
    }

    function setInteractive(nextInteractive) {
      enabled = Boolean(nextInteractive);
      canvas.hidden = !enabled;
      body.classList.toggle('vision-ascii-ready', enabled);

      if (!enabled) {
        particles.length = 0;
        context.clearRect(0, 0, width, height);
        hasPointer = false;
      } else {
        resize();
      }
    }

    resize();

    return {
      resize,
      refreshTheme,
      setInteractive,
      pointerMove: seedTrail,
      pointerDown: splash,
      pointerUp(event) {
        seedTrail(event, 6);
      },
      pointerLeave() {
        hasPointer = false;
      },
      update
    };
  }

  function applyTheme(themeClass) {
    body.classList.remove('theme-light', 'theme-dark');
    body.classList.add(themeClass);

    const theme = themeClass === 'theme-dark' ? 'dark' : 'light';
    body.setAttribute('data-theme', theme);
    document.documentElement.setAttribute('data-theme', theme);
    themeToggle.textContent = themeClass === 'theme-dark'
      ? themeToggle.dataset.lightLabel
      : themeToggle.dataset.darkLabel;
    asciiTrail.refreshTheme();
  }

  function initTheme() {
    const savedTheme = localStorage.getItem('ui-theme');
    const initialTheme = savedTheme === 'theme-light' ? 'theme-light' : 'theme-dark';
    applyTheme(initialTheme);

    themeToggle.addEventListener('click', () => {
      const nextTheme = body.classList.contains('theme-dark') ? 'theme-light' : 'theme-dark';
      applyTheme(nextTheme);
      localStorage.setItem('ui-theme', nextTheme);
    });
  }

  function updateMotionMode() {
    isReducedMotion = reducedMotionQuery.matches;
    isCoarsePointer = coarsePointerQuery.matches;
    interactive = !isReducedMotion && !isCoarsePointer;

    body.classList.toggle('vision-reduced-motion', isReducedMotion);
    body.classList.toggle('vision-coarse-pointer', isCoarsePointer);
    asciiTrail.setInteractive(interactive);
  }

  function onPointerMove(event) {
    if (!interactive) {
      return;
    }

    asciiTrail.pointerMove(event);
  }

  function onPointerLeave() {
    asciiTrail.pointerLeave();
  }

  function onResize() {
    if (resizeTimer) {
      return;
    }

    resizeTimer = window.setTimeout(() => {
      resizeTimer = null;
      asciiTrail.resize();
    }, 120);
  }

  function animationFrame(now) {
    if (!running) {
      return;
    }

    asciiTrail.update(now);
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

    startLoop();
  }

  initTheme();
  updateMotionMode();

  document.addEventListener('pointermove', onPointerMove, { passive: true });
  document.addEventListener('pointerdown', (event) => asciiTrail.pointerDown(event), { passive: true });
  document.addEventListener('pointerup', (event) => asciiTrail.pointerUp(event), { passive: true });
  document.addEventListener('pointercancel', onPointerLeave, { passive: true });
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
