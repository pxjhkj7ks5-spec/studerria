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

  document.addEventListener('click', function(event) {
    var button = event.target.closest('[data-theme-toggle]');
    if (!button) return;
    toggleTheme();
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      applyTheme(readTheme());
    }, { once: true });
  } else {
    applyTheme(readTheme());
  }
})();
