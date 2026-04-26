(function initStuderriaTestDesign() {
  var STORAGE_KEY = 'studerria-test-theme';
  var root = document.documentElement;

  function readTheme() {
    return root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }

  function applyTheme(theme) {
    var nextTheme = theme === 'dark' ? 'dark' : 'light';
    root.setAttribute('data-theme', nextTheme);
    if (document.body) {
      document.body.setAttribute('data-theme', nextTheme);
    }
    try {
      localStorage.setItem(STORAGE_KEY, nextTheme);
    } catch (_error) {}
    document.querySelectorAll('[data-theme-toggle]').forEach(function(button) {
      var isDark = nextTheme === 'dark';
      button.setAttribute('aria-pressed', isDark ? 'true' : 'false');
      button.setAttribute('aria-label', isDark ? 'Увімкнути світлу тему' : 'Увімкнути темну тему');
      button.querySelectorAll('[data-theme-label]').forEach(function(label) {
        label.textContent = isDark ? 'Light' : 'Dark';
      });
    });
  }

  function toggleTheme() {
    applyTheme(readTheme() === 'dark' ? 'light' : 'dark');
  }

  function initCodexCursorLayer() {
    if (!document.body || !document.body.classList.contains('td-page')) return;
    if (document.querySelector('[data-td-codex-cursor]')) return;

    var reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    var coarsePointerQuery = window.matchMedia('(pointer: coarse)');
    if (reducedMotionQuery.matches || coarsePointerQuery.matches) return;

    var canvas = document.createElement('canvas');
    canvas.className = 'td-codex-cursor-canvas';
    canvas.setAttribute('data-td-codex-cursor', 'true');
    canvas.setAttribute('aria-hidden', 'true');
    document.body.prepend(canvas);

    var ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) {
      canvas.remove();
      return;
    }

    var charset = '○>_ ';
    var fontSize = 9;
    var gridStep = 11;
    var fpsInterval = 1000 / 30;
    var dpr = 1;
    var width = 0;
    var height = 0;
    var splats = [];
    var rafId = 0;
    var lastFrame = 0;
    var lastMoveX = window.innerWidth * 0.5;
    var lastMoveY = window.innerHeight * 0.36;
    var lastTrailAt = 0;
    var running = true;

    function resizeCanvas() {
      dpr = Math.min(2, Math.max(1, window.devicePixelRatio || 1));
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      canvas.style.width = width + 'px';
      canvas.style.height = height + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.font = fontSize + 'px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
    }

    function colorFromCss() {
      var color = window.getComputedStyle(canvas).color;
      return color && color !== 'canvastext' ? color : 'rgba(120, 90, 255, 0.65)';
    }

    function addSplat(x, y, vx, vy, radius, strength, life, splash) {
      splats.push({
        x: x,
        y: y,
        vx: vx,
        vy: vy,
        radius: radius,
        strength: strength,
        life: life,
        age: 0,
        splash: Boolean(splash)
      });
      if (splats.length > 34) {
        splats.splice(0, splats.length - 34);
      }
    }

    function sampledLuma(x, y, now) {
      var nx = x / Math.max(1, width);
      var ny = y / Math.max(1, height);
      var wave = Math.sin(nx * 8.2 + now * 0.00055) * 0.16 + Math.cos((ny - nx) * 7.4 - now * 0.00042) * 0.14;
      var leftGlow = Math.exp(-((nx - 0.12) * (nx - 0.12) / 0.026 + (ny - 0.24) * (ny - 0.24) / 0.08)) * 0.34;
      var rightGlow = Math.exp(-((nx - 0.84) * (nx - 0.84) / 0.045 + (ny - 0.68) * (ny - 0.68) / 0.12)) * 0.28;
      var ribbon = Math.exp(-Math.pow((ny - 0.58) - Math.sin(nx * 4.2 + now * 0.00018) * 0.12, 2) / 0.006) * 0.22;
      return Math.max(0, Math.min(1, 0.28 + wave + leftGlow + rightGlow + ribbon));
    }

    function maskAt(x, y) {
      var value = 0;
      for (var i = 0; i < splats.length; i += 1) {
        var splat = splats[i];
        var dx = x - splat.x;
        var dy = y - splat.y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        var fade = Math.max(0, 1 - (splat.age / splat.life));
        var local = 0;

        if (splat.splash) {
          var ringCenter = splat.radius * 0.52;
          var thickness = 100;
          local = Math.exp(-Math.pow((dist - ringCenter) / thickness, 2));
        } else {
          local = Math.exp(-(dx * dx + dy * dy) / (splat.radius * splat.radius));
        }

        value += local * fade * splat.strength;
      }
      return Math.max(0, Math.min(1, value));
    }

    function boundsForSplats() {
      if (splats.length === 0) return null;
      var minX = width;
      var minY = height;
      var maxX = 0;
      var maxY = 0;
      splats.forEach(function(splat) {
        var pad = splat.radius + 60;
        minX = Math.min(minX, splat.x - pad);
        minY = Math.min(minY, splat.y - pad);
        maxX = Math.max(maxX, splat.x + pad);
        maxY = Math.max(maxY, splat.y + pad);
      });
      return {
        minX: Math.max(0, Math.floor(minX / gridStep) * gridStep),
        minY: Math.max(0, Math.floor(minY / gridStep) * gridStep),
        maxX: Math.min(width, Math.ceil(maxX / gridStep) * gridStep),
        maxY: Math.min(height, Math.ceil(maxY / gridStep) * gridStep)
      };
    }

    function draw(now) {
      ctx.clearRect(0, 0, width, height);

      var bounds = boundsForSplats();
      if (!bounds) return;

      ctx.fillStyle = colorFromCss();
      ctx.font = fontSize + 'px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace';

      for (var y = bounds.minY; y <= bounds.maxY; y += gridStep) {
        for (var x = bounds.minX; x <= bounds.maxX; x += gridStep) {
          var density = maskAt(x, y);
          if (density < 0.045) continue;

          var luma = sampledLuma(x, y, now);
          var intensity = Math.max(0, Math.min(1, Math.pow(luma * density, 0.5) * 1.18));
          if (intensity < 0.12) continue;

          var index = intensity > 0.72 ? 0 : intensity > 0.46 ? 1 : 2;
          ctx.globalAlpha = Math.min(0.72, 0.14 + intensity * 0.58);
          ctx.fillText(charset[index], x, y);
        }
      }
      ctx.globalAlpha = 1;
    }

    function step(now) {
      if (!running) return;

      if (now - lastFrame >= fpsInterval) {
        var dt = Math.min(64, now - (lastFrame || now));
        lastFrame = now;

        splats = splats.filter(function(splat) {
          splat.age += dt;
          splat.x += splat.vx * dt * 0.012;
          splat.y += splat.vy * dt * 0.012;
          splat.vx *= 0.975;
          splat.vy *= 0.975;
          return splat.age < splat.life;
        });
        draw(now);
      }

      rafId = window.requestAnimationFrame(step);
    }

    function onPointerMove(event) {
      var now = performance.now();
      var dx = event.clientX - lastMoveX;
      var dy = event.clientY - lastMoveY;
      var distance = Math.sqrt(dx * dx + dy * dy);

      if (distance > 7 || now - lastTrailAt > 44) {
        addSplat(event.clientX, event.clientY, dx, dy, 28, 1.25, 720, false);
        lastTrailAt = now;
      }

      lastMoveX = event.clientX;
      lastMoveY = event.clientY;
    }

    function onPointerDown(event) {
      addSplat(event.clientX, event.clientY, 0, 0, 184, 1.45, 980, true);
    }

    function teardown() {
      running = false;
      if (rafId) {
        window.cancelAnimationFrame(rafId);
      }
      canvas.remove();
      window.removeEventListener('resize', resizeCanvas);
      document.removeEventListener('pointermove', onPointerMove);
      document.removeEventListener('pointerdown', onPointerDown);
    }

    function onMotionModeChange() {
      if (reducedMotionQuery.matches || coarsePointerQuery.matches) {
        teardown();
      }
    }

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas, { passive: true });
    document.addEventListener('pointermove', onPointerMove, { passive: true });
    document.addEventListener('pointerdown', onPointerDown, { passive: true });

    if (typeof reducedMotionQuery.addEventListener === 'function') {
      reducedMotionQuery.addEventListener('change', onMotionModeChange);
      coarsePointerQuery.addEventListener('change', onMotionModeChange);
    }

    addSplat(width * 0.72, height * 0.2, 0, 0, 74, 0.32, 900, false);
    rafId = window.requestAnimationFrame(step);
  }

  function initScheduleNextClass() {
    var chip = document.querySelector('[data-next-class]');
    if (!chip) return;

    var kind = chip.querySelector('[data-next-kind]');
    var label = chip.querySelector('[data-next-label]');
    var cards = Array.prototype.slice.call(document.querySelectorAll('.td-lesson-card'));

    function minutesFromTime(value) {
      var match = String(value || '').match(/(\d{1,2}):(\d{2})/);
      if (!match) return null;
      return Number(match[1]) * 60 + Number(match[2]);
    }

    function textFromCard(card) {
      var timeText = card.querySelector('time') ? card.querySelector('time').textContent : '';
      var title = card.querySelector('.td-lesson-main strong') ? card.querySelector('.td-lesson-main strong').textContent.trim() : '';
      var locationText = card.querySelector('.td-location') ? card.querySelector('.td-location').textContent : '';
      var locationMatch = String(locationText || '').match(/ауд\.\s*\S+/i);
      var times = String(timeText || '').split('-');
      var start = minutesFromTime(times[0]);
      var end = minutesFromTime(times[1]);

      return {
        card: card,
        title: title || 'Пара',
        room: locationMatch ? locationMatch[0].trim() : '',
        startText: times[0] ? times[0].trim() : '',
        endText: times[1] ? times[1].trim() : '',
        start: start,
        end: end
      };
    }

    function setChip(state, text) {
      chip.classList.toggle('is-now', state === 'Now');
      if (kind) kind.textContent = state;
      if (label) label.textContent = text;
    }

    var lessons = cards
      .map(textFromCard)
      .filter(function(lesson) {
        return Number.isFinite(lesson.start) && Number.isFinite(lesson.end);
      })
      .sort(function(a, b) {
        return a.start - b.start;
      });

    if (!lessons.length) {
      setChip('Free', 'No classes today');
      return;
    }

    var now = new Date();
    var currentMinutes = now.getHours() * 60 + now.getMinutes();
    var active = lessons.find(function(lesson) {
      return currentMinutes >= lesson.start && currentMinutes < lesson.end;
    });

    if (active) {
      setChip('Now', 'Now: ' + active.title + ' · до ' + active.endText);
      return;
    }

    var next = lessons.find(function(lesson) {
      return lesson.start > currentMinutes;
    });

    if (next) {
      var roomSuffix = next.room ? ' · ' + next.room : '';
      setChip('Next', 'Next: ' + next.title + ' · ' + next.startText + roomSuffix);
      return;
    }

    setChip('Done', 'Done for today');
  }

  function setSidebar(open) {
    if (!document.body) return;
    document.body.classList.toggle('td-sidebar-open', Boolean(open));
    document.querySelectorAll('[data-sidebar-toggle]').forEach(function(button) {
      button.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
  }

  document.addEventListener('click', function(event) {
    var button = event.target.closest('[data-theme-toggle]');
    if (button) {
      toggleTheme();
      return;
    }

    if (event.target.closest('[data-sidebar-toggle]')) {
      setSidebar(!(document.body && document.body.classList.contains('td-sidebar-open')));
      return;
    }

    if (event.target.closest('[data-sidebar-dismiss]') || event.target.closest('.td-sidebar-link')) {
      setSidebar(false);
    }
  });

  document.addEventListener('pointerdown', function(event) {
    if (!document.body || !document.body.classList.contains('td-sidebar-open')) return;
    if (event.target.closest('.td-sidebar') || event.target.closest('[data-sidebar-toggle]')) return;
    setSidebar(false);
  });

  document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
      setSidebar(false);
    }
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      applyTheme(readTheme());
      initScheduleNextClass();
      initCodexCursorLayer();
    }, { once: true });
  } else {
    applyTheme(readTheme());
    initScheduleNextClass();
    initCodexCursorLayer();
  }
})();
