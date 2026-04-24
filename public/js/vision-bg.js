(() => {
  const body = document.body;
  if (!body || !body.classList.contains('page-vision')) {
    return;
  }

  const themeToggle = document.getElementById('visionThemeToggle');
  if (!themeToggle) {
    return;
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
  }

  const savedTheme = localStorage.getItem('ui-theme');
  applyTheme(savedTheme === 'theme-light' ? 'theme-light' : 'theme-dark');

  themeToggle.addEventListener('click', () => {
    const nextTheme = body.classList.contains('theme-dark') ? 'theme-light' : 'theme-dark';
    applyTheme(nextTheme);
    localStorage.setItem('ui-theme', nextTheme);
  });
})();
