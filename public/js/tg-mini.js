(function initStuderriaTelegramMini() {
  const tg = window.Telegram && window.Telegram.WebApp ? window.Telegram.WebApp : null;
  const state = window.__studerriaTg || {};

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
      if (data.status === 'link_required' && (currentPath === '/studerria-tg' || currentPath === '/studerria-tg/login')) {
        window.location.replace(data.redirect);
      }
    } catch (_error) {}
  }

  function bindChangelog() {
    document.addEventListener('click', (event) => {
      const target = event.target instanceof Element ? event.target : null;
      if (!target) return;
      const modal = document.querySelector('[data-tg-changelog]');
      if (!modal) return;
      const open = target.closest('[data-tg-changelog-open]');
      const close = target.closest('[data-tg-changelog-close]');
      if (open) {
        event.preventDefault();
        modal.hidden = false;
        requestAnimationFrame(() => modal.classList.add('is-open'));
      }
      if (close) {
        event.preventDefault();
        modal.classList.remove('is-open');
        setTimeout(() => {
          modal.hidden = true;
        }, 160);
      }
    });
  }

  window.addEventListener('resize', applyTelegramChrome);
  applyTelegramChrome();
  bindChangelog();
  syncTelegramSession();
})();
