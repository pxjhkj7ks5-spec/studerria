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

  const safeElements = Array.from(document.querySelectorAll('[data-ascii-safe]'));
  const shapeStates = Array.from(bgRoot.querySelectorAll('.bg-shape-wrap')).map((element) => ({
    element,
    depth: Number(element.dataset.depth || 0.016),
    x: 0,
    y: 0
  }));

  const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarsePointerQuery = window.matchMedia('(pointer: coarse)');

  const ASCII_CONFIG = {
    charset: '○>_ ',
    fontSize: 9,
    fps: 30,
    hoverRadiusPx: 28,
    splashRangePx: 184,
    splashThicknessPx: 100,
    diffusion: 0.16,
    iterations: 2,
    velocityDissipation: 0.9,
    densityDissipation: 0.925
  };

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

  const morphStates = Array.from(bgRoot.querySelectorAll('[data-blob-path]')).map((pathEl, index) => {
    const kind = pathEl.dataset.blobPath === 'secondary' ? 'secondary' : 'primary';
    const frames = BLOB_MORPH_SHAPES[kind] || BLOB_MORPH_SHAPES.primary;
    pathEl.setAttribute('d', toBlobPath(frames[0]));
    return {
      pathEl,
      frames,
      duration: kind === 'secondary' ? 68000 : 54000,
      offset: index * 7800
    };
  });

  const DUST_POINTS = Array.from({ length: 30 }, (_, index) => {
    const seed = index + 1;
    const x = fract(Math.sin(seed * 12.9898) * 43758.5453);
    const y = fract(Math.sin(seed * 78.233) * 12831.5937);
    const size = 0.4 + (fract(Math.sin(seed * 4.73) * 4152.114) * 1.1);
    const alpha = 0.08 + (fract(Math.sin(seed * 1.37) * 9421.4) * 0.24);
    return { x, y, size, alpha };
  });

  let viewportWidth = window.innerWidth;
  let viewportHeight = window.innerHeight;
  let centerX = viewportWidth / 2;
  let centerY = viewportHeight / 2;
  let pointerX = centerX;
  let pointerY = centerY;
  let smoothX = centerX;
  let smoothY = centerY;
  let pointerInside = false;
  let isReducedMotion = reducedMotionQuery.matches;
  let isCoarsePointer = coarsePointerQuery.matches;
  let interactive = !isReducedMotion && !isCoarsePointer;
  let lastMorphAt = 0;
  let resizeTimer = null;
  let rafId = 0;
  let running = false;

  const asciiFluid = createAsciiFluid(asciiCanvas, heroElement, safeElements);

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function fract(value) {
    return value - Math.floor(value);
  }

  function smoothstep(value) {
    return value * value * (3 - (2 * value));
  }

  function toBlobPath(values) {
    return `M${values[0].toFixed(2)} ${values[1].toFixed(2)} C${values[2].toFixed(2)} ${values[3].toFixed(2)} ${values[4].toFixed(2)} ${values[5].toFixed(2)} ${values[6].toFixed(2)} ${values[7].toFixed(2)} C${values[8].toFixed(2)} ${values[9].toFixed(2)} ${values[10].toFixed(2)} ${values[11].toFixed(2)} ${values[12].toFixed(2)} ${values[13].toFixed(2)} C${values[14].toFixed(2)} ${values[15].toFixed(2)} ${values[16].toFixed(2)} ${values[17].toFixed(2)} ${values[18].toFixed(2)} ${values[19].toFixed(2)} C${values[20].toFixed(2)} ${values[21].toFixed(2)} ${values[22].toFixed(2)} ${values[23].toFixed(2)} ${values[24].toFixed(2)} ${values[25].toFixed(2)} Z`;
  }

  function createAsciiFluid(canvas, hero, safeNodes) {
    const noop = {
      resize() {},
      refreshTheme() {},
      setInteractive() {},
      pointerMove() {},
      pointerDown() {},
      pointerUp() {},
      pointerLeave() {},
      update() {}
    };

    const context = canvas.getContext('2d', { alpha: true });
    const fieldCanvas = document.createElement('canvas');
    const fieldContext = fieldCanvas.getContext('2d', { alpha: true, willReadFrequently: true });
    if (!context || !fieldContext) {
      return noop;
    }

    const config = ASCII_CONFIG;
    const frameInterval = 1000 / config.fps;
    let width = 0;
    let height = 0;
    let dpr = 1;
    let cols = 0;
    let rows = 0;
    let size = 0;
    let enabled = false;
    let lastFrameAt = 0;
    let lastPointerX = 0;
    let lastPointerY = 0;
    let hasPointer = false;
    let colorRgb = '205, 214, 255';
    let density = new Float32Array(0);
    let densityNext = new Float32Array(0);
    let velocityX = new Float32Array(0);
    let velocityY = new Float32Array(0);
    let velocityXNext = new Float32Array(0);
    let velocityYNext = new Float32Array(0);

    function indexOf(x, y) {
      return y * cols + x;
    }

    function swapFields() {
      let swap = density;
      density = densityNext;
      densityNext = swap;

      swap = velocityX;
      velocityX = velocityXNext;
      velocityXNext = swap;

      swap = velocityY;
      velocityY = velocityYNext;
      velocityYNext = swap;
    }

    function sample(field, x, y) {
      const x0 = clamp(Math.floor(x), 0, cols - 1);
      const y0 = clamp(Math.floor(y), 0, rows - 1);
      const x1 = clamp(x0 + 1, 0, cols - 1);
      const y1 = clamp(y0 + 1, 0, rows - 1);
      const tx = clamp(x - x0, 0, 1);
      const ty = clamp(y - y0, 0, 1);
      const a = field[indexOf(x0, y0)];
      const b = field[indexOf(x1, y0)];
      const c = field[indexOf(x0, y1)];
      const d = field[indexOf(x1, y1)];
      return (a * (1 - tx) * (1 - ty)) + (b * tx * (1 - ty)) + (c * (1 - tx) * ty) + (d * tx * ty);
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
        right: width,
        bottom: Math.min(height * 0.86, 880),
        width,
        height: Math.min(height * 0.86, 880)
      };
    }

    function pointWithinRect(x, y, rect, padding = 0) {
      return (
        x >= rect.left - padding &&
        x <= rect.right + padding &&
        y >= rect.top - padding &&
        y <= rect.bottom + padding
      );
    }

    function collectSafeRects() {
      return safeNodes
        .map((node) => node.getBoundingClientRect())
        .filter((rect) => rect.width > 0 && rect.height > 0);
    }

    function safeFactorAt(x, y, safeRects) {
      let factor = 1;

      for (const rect of safeRects) {
        const padding = rect.width > 520 ? 96 : 56;
        const dx = Math.max(rect.left - x, 0, x - rect.right);
        const dy = Math.max(rect.top - y, 0, y - rect.bottom);
        const distance = Math.hypot(dx, dy);

        if (distance <= 0.01) {
          return 0;
        }

        if (distance < padding) {
          factor = Math.min(factor, smoothstep(distance / padding));
        }
      }

      return factor;
    }

    function heroMaskAt(x, y, rect) {
      const relativeX = (x - rect.left) / Math.max(1, rect.width);
      const relativeY = (y - rect.top) / Math.max(1, rect.height);
      if (relativeX < -0.08 || relativeX > 1.08 || relativeY < -0.16 || relativeY > 1.1) {
        return 0;
      }

      const xFade = smoothstep(clamp(1 - (Math.abs(relativeX - 0.5) / 0.66), 0, 1));
      const topFade = smoothstep(clamp((relativeY + 0.1) / 0.2, 0, 1));
      const bottomFade = smoothstep(clamp((1.08 - relativeY) / 0.36, 0, 1));
      return xFade * topFade * bottomFade;
    }

    function resize() {
      width = window.innerWidth;
      height = window.innerHeight;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      cols = Math.max(1, Math.ceil(width / config.fontSize));
      rows = Math.max(1, Math.ceil(height / config.fontSize));
      size = cols * rows;

      canvas.width = Math.ceil(width * dpr);
      canvas.height = Math.ceil(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
      context.font = `${config.fontSize}px "SF Mono", "Menlo", "Consolas", monospace`;
      context.textBaseline = 'top';

      fieldCanvas.width = cols;
      fieldCanvas.height = rows;

      density = new Float32Array(size);
      densityNext = new Float32Array(size);
      velocityX = new Float32Array(size);
      velocityY = new Float32Array(size);
      velocityXNext = new Float32Array(size);
      velocityYNext = new Float32Array(size);
      refreshTheme();
    }

    function refreshTheme() {
      const computed = window.getComputedStyle(canvas);
      colorRgb = computed.getPropertyValue('--ascii-fluid-rgb').trim() || colorRgb;
    }

    function addForce(x, y, dx, dy, radiusPx, amount) {
      if (!enabled || !size) {
        return;
      }

      const heroRect = getHeroRect();
      if (!pointWithinRect(x, y, heroRect, 48)) {
        return;
      }

      const cx = x / config.fontSize;
      const cy = y / config.fontSize;
      const radius = Math.max(1, radiusPx / config.fontSize);
      const minX = clamp(Math.floor(cx - radius), 0, cols - 1);
      const maxX = clamp(Math.ceil(cx + radius), 0, cols - 1);
      const minY = clamp(Math.floor(cy - radius), 0, rows - 1);
      const maxY = clamp(Math.ceil(cy + radius), 0, rows - 1);
      const forceX = clamp(dx / config.fontSize, -7, 7);
      const forceY = clamp(dy / config.fontSize, -7, 7);

      for (let yy = minY; yy <= maxY; yy += 1) {
        for (let xx = minX; xx <= maxX; xx += 1) {
          const localX = xx - cx;
          const localY = yy - cy;
          const distance = Math.hypot(localX, localY);
          if (distance > radius) {
            continue;
          }

          const falloff = Math.pow(1 - (distance / radius), 2);
          const index = indexOf(xx, yy);
          density[index] = clamp(density[index] + (amount * falloff), 0, 1.65);
          velocityX[index] += forceX * falloff * 0.68;
          velocityY[index] += forceY * falloff * 0.68;
        }
      }
    }

    function splash(x, y) {
      if (!enabled || !size) {
        return;
      }

      const heroRect = getHeroRect();
      if (!pointWithinRect(x, y, heroRect, 60)) {
        return;
      }

      const cx = x / config.fontSize;
      const cy = y / config.fontSize;
      const range = config.splashRangePx / config.fontSize;
      const thickness = Math.max(1, config.splashThicknessPx / config.fontSize);
      const minX = clamp(Math.floor(cx - range), 0, cols - 1);
      const maxX = clamp(Math.ceil(cx + range), 0, cols - 1);
      const minY = clamp(Math.floor(cy - range), 0, rows - 1);
      const maxY = clamp(Math.ceil(cy + range), 0, rows - 1);
      const ringTarget = range * 0.5;

      for (let yy = minY; yy <= maxY; yy += 1) {
        for (let xx = minX; xx <= maxX; xx += 1) {
          const localX = xx - cx;
          const localY = yy - cy;
          const distance = Math.hypot(localX, localY);
          if (distance > range) {
            continue;
          }

          const ring = Math.exp(-Math.pow((distance - ringTarget) / thickness, 2));
          const radial = distance > 0.01 ? 1 / distance : 0;
          const index = indexOf(xx, yy);
          density[index] = clamp(density[index] + (ring * 1.18), 0, 1.8);
          velocityX[index] += localX * radial * ring * 3.15;
          velocityY[index] += localY * radial * ring * 3.15;
        }
      }
    }

    function diffuseField(source, target, rate) {
      for (let y = 0; y < rows; y += 1) {
        for (let x = 0; x < cols; x += 1) {
          const index = indexOf(x, y);
          const left = source[indexOf(Math.max(0, x - 1), y)];
          const right = source[indexOf(Math.min(cols - 1, x + 1), y)];
          const up = source[indexOf(x, Math.max(0, y - 1))];
          const down = source[indexOf(x, Math.min(rows - 1, y + 1))];
          const average = (left + right + up + down) * 0.25;
          target[index] = source[index] + ((average - source[index]) * rate);
        }
      }
    }

    function stepFluid() {
      for (let iteration = 0; iteration < config.iterations; iteration += 1) {
        diffuseField(density, densityNext, config.diffusion);
        diffuseField(velocityX, velocityXNext, config.diffusion * 0.72);
        diffuseField(velocityY, velocityYNext, config.diffusion * 0.72);
        swapFields();
      }

      for (let y = 0; y < rows; y += 1) {
        for (let x = 0; x < cols; x += 1) {
          const index = indexOf(x, y);
          const prevX = x - (velocityX[index] * 0.24);
          const prevY = y - (velocityY[index] * 0.24);
          densityNext[index] = sample(density, prevX, prevY) * config.densityDissipation;
          velocityXNext[index] = sample(velocityX, prevX, prevY) * config.velocityDissipation;
          velocityYNext[index] = sample(velocityY, prevX, prevY) * config.velocityDissipation;
        }
      }

      swapFields();
    }

    function renderRibbonPath(kind, gx, gy, gw, gh, drift) {
      const path = new Path2D();

      if (kind === 'secondary') {
        path.moveTo(gx - (gw * 0.06), gy + (gh * 0.78) - (drift * 0.42));
        path.bezierCurveTo(
          gx + (gw * 0.16), gy + (gh * 0.96),
          gx + (gw * 0.34), gy + (gh * 0.48),
          gx + (gw * 0.58), gy + (gh * 0.72)
        );
        path.bezierCurveTo(
          gx + (gw * 0.82), gy + (gh * 0.9),
          gx + (gw * 0.94), gy + (gh * 0.54),
          gx + (gw * 1.06), gy + (gh * 0.68) + (drift * 0.22)
        );
        return path;
      }

      path.moveTo(gx - (gw * 0.12), gy + (gh * 0.42) + drift);
      path.bezierCurveTo(
        gx + (gw * 0.08), gy + (gh * 0.1) - drift,
        gx + (gw * 0.32), gy + (gh * 0.7) + (drift * 0.55),
        gx + (gw * 0.56), gy + (gh * 0.56) - (drift * 0.24)
      );
      path.bezierCurveTo(
        gx + (gw * 0.78), gy + (gh * 0.42),
        gx + (gw * 0.92), gy + (gh * 0.18) - drift,
        gx + (gw * 1.08), gy + (gh * 0.34) + (drift * 0.3)
      );
      return path;
    }

    function renderField(now, heroRect) {
      const themeDark = body.classList.contains('theme-dark');
      const gx = heroRect.left / config.fontSize;
      const gy = heroRect.top / config.fontSize;
      const gw = heroRect.width / config.fontSize;
      const gh = heroRect.height / config.fontSize;

      fieldContext.clearRect(0, 0, cols, rows);

      const baseGradient = fieldContext.createLinearGradient(0, gy, 0, gy + gh);
      if (themeDark) {
        baseGradient.addColorStop(0, 'rgba(12, 15, 29, 0.96)');
        baseGradient.addColorStop(0.54, 'rgba(18, 22, 41, 0.92)');
        baseGradient.addColorStop(1, 'rgba(23, 18, 44, 0.9)');
      } else {
        baseGradient.addColorStop(0, 'rgba(245, 247, 255, 0.98)');
        baseGradient.addColorStop(0.56, 'rgba(235, 240, 255, 0.92)');
        baseGradient.addColorStop(1, 'rgba(239, 235, 255, 0.9)');
      }

      fieldContext.fillStyle = baseGradient;
      fieldContext.fillRect(Math.max(0, gx - 8), Math.max(0, gy - 8), gw + 16, gh + 16);

      const ambientGlow = fieldContext.createRadialGradient(
        gx + (gw * 0.5),
        gy + (gh * 0.26),
        0,
        gx + (gw * 0.5),
        gy + (gh * 0.26),
        gw * 0.6
      );
      if (themeDark) {
        ambientGlow.addColorStop(0, 'rgba(118, 114, 255, 0.34)');
        ambientGlow.addColorStop(0.46, 'rgba(92, 64, 190, 0.16)');
        ambientGlow.addColorStop(1, 'rgba(5, 8, 18, 0)');
      } else {
        ambientGlow.addColorStop(0, 'rgba(140, 148, 255, 0.16)');
        ambientGlow.addColorStop(0.48, 'rgba(164, 126, 255, 0.08)');
        ambientGlow.addColorStop(1, 'rgba(245, 247, 255, 0)');
      }
      fieldContext.fillStyle = ambientGlow;
      fieldContext.fillRect(Math.max(0, gx - 12), Math.max(0, gy - 8), gw + 24, gh + 18);

      const ribbonDrift = Math.sin(now * 0.00008) * gh * 0.05;
      const primaryRibbon = renderRibbonPath('primary', gx, gy, gw, gh, ribbonDrift);
      const secondaryRibbon = renderRibbonPath('secondary', gx, gy, gw, gh, ribbonDrift);

      fieldContext.save();
      fieldContext.lineCap = 'round';
      fieldContext.lineJoin = 'round';
      fieldContext.shadowBlur = themeDark ? gh * 0.34 : gh * 0.22;
      fieldContext.shadowColor = themeDark ? 'rgba(147, 92, 255, 0.28)' : 'rgba(144, 130, 240, 0.18)';

      fieldContext.strokeStyle = themeDark ? 'rgba(112, 96, 255, 0.22)' : 'rgba(132, 122, 240, 0.13)';
      fieldContext.lineWidth = Math.max(7, gh * 0.22);
      fieldContext.stroke(primaryRibbon);

      fieldContext.strokeStyle = themeDark ? 'rgba(150, 104, 255, 0.18)' : 'rgba(170, 146, 255, 0.1)';
      fieldContext.lineWidth = Math.max(6, gh * 0.16);
      fieldContext.stroke(secondaryRibbon);

      fieldContext.shadowBlur = 0;
      fieldContext.strokeStyle = themeDark ? 'rgba(244, 238, 255, 0.26)' : 'rgba(255, 255, 255, 0.16)';
      fieldContext.lineWidth = Math.max(1.4, gh * 0.028);
      fieldContext.stroke(primaryRibbon);

      fieldContext.strokeStyle = themeDark ? 'rgba(222, 216, 255, 0.2)' : 'rgba(255, 255, 255, 0.14)';
      fieldContext.lineWidth = Math.max(1.2, gh * 0.022);
      fieldContext.stroke(secondaryRibbon);
      fieldContext.restore();

      fieldContext.save();
      fieldContext.fillStyle = themeDark ? 'rgba(240, 238, 255, 0.56)' : 'rgba(92, 86, 184, 0.24)';
      DUST_POINTS.forEach((point) => {
        const px = gx + (gw * point.x);
        const py = gy + (gh * point.y);
        const sizePx = point.size * (themeDark ? 0.9 : 0.75);
        fieldContext.globalAlpha = point.alpha;
        fieldContext.beginPath();
        fieldContext.arc(px, py, sizePx, 0, Math.PI * 2);
        fieldContext.fill();
      });
      fieldContext.restore();

      return fieldContext.getImageData(0, 0, cols, rows).data;
    }

    function draw(now) {
      const heroRect = getHeroRect();
      const safeRects = collectSafeRects();
      const lumaField = renderField(now, heroRect);
      const themeDark = body.classList.contains('theme-dark');

      context.clearRect(0, 0, width, height);
      context.font = `${config.fontSize}px "SF Mono", "Menlo", "Consolas", monospace`;

      for (let y = 0; y < rows; y += 1) {
        for (let x = 0; x < cols; x += 1) {
          const index = indexOf(x, y);
          const px = x * config.fontSize;
          const py = y * config.fontSize;
          const cellX = px + (config.fontSize * 0.5);
          const cellY = py + (config.fontSize * 0.58);

          const heroMask = heroMaskAt(cellX, cellY, heroRect);
          if (heroMask <= 0.015) {
            continue;
          }

          const safeFactor = safeFactorAt(cellX, cellY, safeRects);
          if (safeFactor <= 0.01) {
            continue;
          }

          const fieldIndex = index * 4;
          const alphaChannel = lumaField[fieldIndex + 3] / 255;
          if (alphaChannel <= 0.01) {
            continue;
          }

          const red = lumaField[fieldIndex];
          const green = lumaField[fieldIndex + 1];
          const blue = lumaField[fieldIndex + 2];
          const luma = (((red * 0.299) + (green * 0.587) + (blue * 0.114)) / 255) * alphaChannel;
          const reveal = clamp(density[index], 0, 1.35);
          const ambient = Math.pow(clamp(luma, 0, 1), 1.08);
          const intensity = clamp((ambient * 0.16) + (ambient * reveal * 1.08) + (reveal * 0.08), 0, 1);
          const charTone = clamp((ambient * 0.84) + (reveal * 0.22), 0, 1);
          const charIndex = clamp(
            Math.floor((1 - charTone) * (config.charset.length - 1)),
            0,
            config.charset.length - 1
          );
          const character = config.charset[charIndex];
          if (character === ' ') {
            continue;
          }

          const alpha = clamp(
            intensity * heroMask * safeFactor * (themeDark ? 0.56 : 0.34),
            0,
            themeDark ? 0.46 : 0.24
          );
          if (alpha <= 0.028) {
            continue;
          }

          context.fillStyle = `rgba(${colorRgb}, ${alpha.toFixed(3)})`;
          context.fillText(character, px, py);
        }
      }
    }

    function pointerMove(event) {
      if (!enabled) {
        return;
      }

      const heroRect = getHeroRect();
      if (!pointWithinRect(event.clientX, event.clientY, heroRect, 44)) {
        hasPointer = false;
        return;
      }

      if (!hasPointer) {
        lastPointerX = event.clientX;
        lastPointerY = event.clientY;
        hasPointer = true;
        return;
      }

      const dx = event.clientX - lastPointerX;
      const dy = event.clientY - lastPointerY;
      const distance = Math.hypot(dx, dy);
      const steps = Math.min(18, Math.max(1, Math.ceil(distance / 9)));

      for (let step = 1; step <= steps; step += 1) {
        const progress = step / steps;
        addForce(
          lastPointerX + (dx * progress),
          lastPointerY + (dy * progress),
          dx / steps,
          dy / steps,
          config.hoverRadiusPx,
          0.44
        );
      }

      lastPointerX = event.clientX;
      lastPointerY = event.clientY;
    }

    function pointerDown(event) {
      if (!enabled) {
        return;
      }

      const heroRect = getHeroRect();
      if (!pointWithinRect(event.clientX, event.clientY, heroRect, 52)) {
        return;
      }

      hasPointer = true;
      lastPointerX = event.clientX;
      lastPointerY = event.clientY;
      splash(event.clientX, event.clientY);
    }

    function pointerUp(event) {
      if (!enabled) {
        return;
      }

      addForce(event.clientX, event.clientY, 0, 0, config.hoverRadiusPx * 1.45, 0.48);
    }

    function pointerLeave() {
      hasPointer = false;
    }

    function setInteractive(nextInteractive) {
      enabled = Boolean(nextInteractive);
      canvas.hidden = !enabled;
      body.classList.toggle('vision-ascii-ready', enabled);

      if (!enabled) {
        context.clearRect(0, 0, width, height);
        hasPointer = false;
      } else if (!size) {
        resize();
      }
    }

    function update(now) {
      if (!enabled || !size || now - lastFrameAt < frameInterval) {
        return;
      }

      lastFrameAt = now;
      stepFluid();
      draw(now);
    }

    resize();

    return {
      resize,
      refreshTheme,
      setInteractive,
      pointerMove,
      pointerDown,
      pointerUp,
      pointerLeave,
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
    asciiFluid.refreshTheme();
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

  function updateMotionMode() {
    isReducedMotion = reducedMotionQuery.matches;
    isCoarsePointer = coarsePointerQuery.matches;
    interactive = !isReducedMotion && !isCoarsePointer;

    body.classList.toggle('vision-reduced-motion', !interactive);
    body.classList.toggle('vision-coarse-pointer', isCoarsePointer);
    asciiFluid.setInteractive(interactive);

    if (!interactive) {
      pointerInside = false;
      pointerX = centerX;
      pointerY = centerY;
      smoothX = centerX;
      smoothY = centerY;
      asciiFluid.pointerLeave();
    }
  }

  function onPointerMove(event) {
    if (!interactive) {
      return;
    }

    pointerInside = true;
    pointerX = event.clientX;
    pointerY = event.clientY;
    asciiFluid.pointerMove(event);
  }

  function onPointerLeave() {
    pointerInside = false;
    pointerX = centerX;
    pointerY = centerY;
    asciiFluid.pointerLeave();
  }

  function onResize() {
    if (resizeTimer) {
      return;
    }

    resizeTimer = window.setTimeout(() => {
      resizeTimer = null;
      updateViewportMetrics();
      asciiFluid.resize();
    }, 140);
  }

  function updateShapeParallax() {
    const offsetX = smoothX - centerX;
    const offsetY = smoothY - centerY;

    shapeStates.forEach((shapeState, index) => {
      const direction = index % 2 === 0 ? 1 : -1;
      const targetX = offsetX * shapeState.depth * 0.56 * direction;
      const targetY = offsetY * shapeState.depth * 0.48;
      shapeState.x += (targetX - shapeState.x) * 0.065;
      shapeState.y += (targetY - shapeState.y) * 0.065;
      shapeState.element.style.transform = `translate3d(${shapeState.x.toFixed(2)}px, ${shapeState.y.toFixed(2)}px, 0)`;
    });
  }

  function updateBlobMorph(now) {
    if (now - lastMorphAt < 54) {
      return;
    }

    lastMorphAt = now;

    morphStates.forEach((state) => {
      const frameCount = state.frames.length;
      if (frameCount < 2) {
        return;
      }

      const cycle = ((now + state.offset) % state.duration) / state.duration;
      const progress = cycle * frameCount;
      const fromIndex = Math.floor(progress) % frameCount;
      const toIndex = (fromIndex + 1) % frameCount;
      const localT = smoothstep(progress - Math.floor(progress));
      const from = state.frames[fromIndex];
      const to = state.frames[toIndex];
      const mixed = new Array(from.length);

      for (let index = 0; index < from.length; index += 1) {
        mixed[index] = from[index] + ((to[index] - from[index]) * localT);
      }

      state.pathEl.setAttribute('d', toBlobPath(mixed));
    });
  }

  function animationFrame(now) {
    if (!running) {
      return;
    }

    if (interactive) {
      smoothX += (pointerX - smoothX) * 0.065;
      smoothY += (pointerY - smoothY) * 0.065;
      asciiFluid.update(now);
    } else {
      smoothX += (centerX - smoothX) * 0.08;
      smoothY += (centerY - smoothY) * 0.08;
    }

    if (!isReducedMotion) {
      updateBlobMorph(now);
      updateShapeParallax();
    }

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
  document.addEventListener('pointerdown', (event) => asciiFluid.pointerDown(event), { passive: true });
  document.addEventListener('pointerup', (event) => asciiFluid.pointerUp(event), { passive: true });
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
