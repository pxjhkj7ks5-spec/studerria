(function initStuderriaTelegramMini() {
  const tg = window.Telegram && window.Telegram.WebApp ? window.Telegram.WebApp : null;
  const state = window.__studerriaTg || {};

  function colorIsDark(rawColor) {
    const hex = String(rawColor || '').trim().replace('#', '');
    if (!/^[0-9a-f]{6}$/i.test(hex)) return false;
    const red = parseInt(hex.slice(0, 2), 16);
    const green = parseInt(hex.slice(2, 4), 16);
    const blue = parseInt(hex.slice(4, 6), 16);
    return ((red * 299 + green * 587 + blue * 114) / 1000) < 145;
  }

  function applyTelegramChrome() {
    if (!tg) return;
    try {
      tg.ready();
      tg.expand();
      document.documentElement.style.setProperty('--tg-viewport-height', `${tg.viewportStableHeight || tg.viewportHeight || window.innerHeight}px`);
      const bg = tg.themeParams && tg.themeParams.bg_color;
      const text = tg.themeParams && tg.themeParams.text_color;
      const button = tg.themeParams && tg.themeParams.button_color;
      if (bg) document.documentElement.style.setProperty('--tg-theme-bg', bg);
      if (text) document.documentElement.style.setProperty('--tg-theme-text', text);
      if (button) document.documentElement.style.setProperty('--tg-theme-accent', button);
      document.documentElement.classList.toggle('is-tg-dark', colorIsDark(bg));
    } catch (_error) {}
  }

  async function syncTelegramSession() {
    if (!tg || !tg.initData) return;
    try {
      const response = await fetch('/studerria-tg/auth/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ initData: tg.initData }),
      });
      const data = await response.json().catch(() => null);
      if (!data || !data.redirect) return;
      const currentPath = window.location.pathname || '';
      if (data.status === 'authenticated' && currentPath !== data.redirect) {
        window.location.replace(data.redirect);
        return;
      }
      if (data.status === 'link_required') {
        if (currentPath === '/studerria-tg' || currentPath === '/studerria-tg/login') {
          window.location.replace(data.redirect);
          return;
        }
        if (currentPath === '/studerria-tg/register' && !sessionStorage.getItem('studerriaTgRegisterSynced')) {
          sessionStorage.setItem('studerriaTgRegisterSynced', '1');
          window.location.reload();
        }
      }
      if (data.ok === false && data.error) {
        document.documentElement.dataset.tgAuthError = data.error;
      }
    } catch (_error) {
      document.documentElement.dataset.tgAuthError = 'network';
    }
  }

  window.addEventListener('resize', applyTelegramChrome);
  applyTelegramChrome();
  syncTelegramSession();
})();
