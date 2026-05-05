(function initStuderriaLoginAuth() {
  var STORAGE_KEY = 'studerria-test-theme';
  var root = document.documentElement;
  var locale = (String(root.getAttribute('lang') || 'uk').toLowerCase().indexOf('en') === 0) ? 'en' : 'uk';
  var uiText = {
    uk: {
      showPassword: 'Показати пароль',
      hidePassword: 'Сховати пароль',
      toggleToLight: 'Увімкнути світлу тему',
      toggleToDark: 'Увімкнути темну тему'
    },
    en: {
      showPassword: 'Show password',
      hidePassword: 'Hide password',
      toggleToLight: 'Switch to light theme',
      toggleToDark: 'Switch to dark theme'
    }
  };

  function text(key) {
    return (uiText[locale] && uiText[locale][key]) || uiText.uk[key] || '';
  }

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
      button.setAttribute('aria-label', isDark ? text('toggleToLight') : text('toggleToDark'));
      button.querySelectorAll('[data-theme-label]').forEach(function(label) {
        label.textContent = isDark ? 'Light' : 'Dark';
      });
    });
  }

  function initLanguageToggle() {
    document.addEventListener('click', function(event) {
      var button = event.target && event.target.closest ? event.target.closest('[data-lang-toggle]') : null;
      if (!button) return;
      event.preventDefault();

      var current = String(button.getAttribute('data-current-lang') || document.documentElement.lang || 'uk').trim().toLowerCase();
      var next = current === 'en' ? 'uk' : 'en';
      var url = new URL(window.location.href);
      url.searchParams.set('lang', next);
      window.location.assign(url.toString());
    });
  }

  function initPasswordReveal() {
    var input = document.querySelector('[data-password-input]');
    var button = document.querySelector('[data-password-reveal]');
    if (!input || !button) return;

    function sync() {
      var hasValue = input.value.length > 0;
      button.hidden = !hasValue;
      button.classList.toggle('is-visible', hasValue);
      button.classList.toggle('is-showing', input.type === 'text');
    }

    button.addEventListener('click', function() {
      var shouldShow = input.type === 'password';
      input.type = shouldShow ? 'text' : 'password';
      button.setAttribute('aria-label', shouldShow ? text('hidePassword') : text('showPassword'));
      sync();
      input.focus();
    });

    input.addEventListener('input', sync);
    input.addEventListener('change', sync);
    sync();
  }

  function initChangelog() {
    var modal = document.querySelector('[data-auth-changelog]');
    if (!modal) return;
    var sheet = modal.querySelector('.td-lite-sheet');
    var lastFocus = null;

    function openModal() {
      lastFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      modal.hidden = false;
      document.body.classList.add('studerria-changelog-open');
      document.body.style.overflow = 'hidden';
      window.requestAnimationFrame(function() {
        modal.classList.add('is-open');
        if (sheet) sheet.focus({ preventScroll: true });
      });
    }

    function closeModal() {
      modal.classList.remove('is-open');
      document.body.classList.remove('studerria-changelog-open');
      document.body.style.overflow = '';
      window.setTimeout(function() {
        modal.hidden = true;
        if (lastFocus) lastFocus.focus({ preventScroll: true });
      }, 180);
    }

    document.addEventListener('click', function(event) {
      var open = event.target && event.target.closest ? event.target.closest('[data-auth-changelog-open]') : null;
      if (open) {
        event.preventDefault();
        openModal();
        return;
      }
      var close = event.target && event.target.closest ? event.target.closest('[data-auth-changelog-close]') : null;
      if (close && !modal.hidden) {
        event.preventDefault();
        closeModal();
      }
    });

    document.addEventListener('keydown', function(event) {
      if (event.key === 'Escape' && !modal.hidden) {
        closeModal();
      }
    });
  }

  function initCodexCursor() {
    if (!document.body || !document.body.classList.contains('td-page')) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (window.matchMedia('(pointer: coarse)').matches) return;

    var canvas = document.createElement('canvas');
    canvas.className = 'td-codex-cursor-canvas';
    canvas.setAttribute('aria-hidden', 'true');
    document.body.prepend(canvas);

    var ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) {
      canvas.remove();
      return;
    }

    var width = 0;
    var height = 0;
    var dpr = 1;
    var rafId = 0;
    var splats = [];
    var lastX = window.innerWidth / 2;
    var lastY = window.innerHeight / 2;
    var lastMoveAt = 0;
    var glyphs = ['○', '>', '_'];

    function resize() {
      dpr = Math.min(2, Math.max(1, window.devicePixelRatio || 1));
      width = window.innerWidth || 1;
      height = window.innerHeight || 1;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = width + 'px';
      canvas.style.height = height + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.font = '10px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
    }

    function color() {
      var value = window.getComputedStyle(canvas).color;
      return value && value !== 'canvastext' ? value : 'rgba(98, 117, 255, 0.52)';
    }

    function addSplat(x, y, radius, life) {
      splats.push({ x: x, y: y, radius: radius, life: life, age: 0 });
      if (splats.length > 7) splats.splice(0, splats.length - 7);
      if (!rafId) rafId = window.requestAnimationFrame(draw);
    }

    function draw(now) {
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = color();
      var active = [];

      splats.forEach(function(splat) {
        splat.age += 16;
        var progress = Math.min(1, splat.age / splat.life);
        var alpha = (1 - progress) * 0.7;
        if (alpha <= 0.02) return;
        active.push(splat);
        var step = 13;
        var radius = splat.radius * (0.82 + progress * 0.38);
        ctx.globalAlpha = alpha;
        for (var y = splat.y - radius; y <= splat.y + radius; y += step) {
          for (var x = splat.x - radius; x <= splat.x + radius; x += step) {
            var dx = x - splat.x;
            var dy = y - splat.y;
            var dist = Math.sqrt(dx * dx + dy * dy);
            if (dist > radius || Math.random() > 0.32) continue;
            var index = Math.min(glyphs.length - 1, Math.floor((dist / radius) * glyphs.length));
            ctx.fillText(glyphs[index], x, y);
          }
        }
      });

      ctx.globalAlpha = 1;
      splats = active;
      if (splats.length) {
        rafId = window.requestAnimationFrame(draw);
      } else {
        rafId = 0;
      }
    }

    document.addEventListener('pointermove', function(event) {
      var now = performance.now();
      var dx = event.clientX - lastX;
      var dy = event.clientY - lastY;
      var distance = Math.sqrt(dx * dx + dy * dy);
      if (distance > 10 && now - lastMoveAt > 42) {
        addSplat(event.clientX, event.clientY, 34, 520);
        lastMoveAt = now;
      }
      lastX = event.clientX;
      lastY = event.clientY;
    }, { passive: true });

    document.addEventListener('pointerdown', function(event) {
      addSplat(event.clientX, event.clientY, 92, 620);
    }, { passive: true });

    window.addEventListener('resize', resize, { passive: true });
    resize();
  }

  applyTheme(readTheme());
  initLanguageToggle();
  initPasswordReveal();
  initChangelog();
})();
