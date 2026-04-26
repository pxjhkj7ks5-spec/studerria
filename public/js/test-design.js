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
    }, { once: true });
  } else {
    applyTheme(readTheme());
  }
})();
