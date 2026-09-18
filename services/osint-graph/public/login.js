(() => {
  'use strict';
  const form = document.getElementById('loginForm');
  const status = document.getElementById('loginStatus');
  const button = form.querySelector('button[type="submit"]');
  const basePath = document.body.dataset.basePath || '/osint';

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!form.reportValidity() || button.disabled) return;
    button.disabled = true;
    button.classList.add('loading');
    status.textContent = '';
    const fields = new FormData(form);
    try {
      const response = await fetch(`${basePath}/api/auth/login`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ username: fields.get('username'), password: fields.get('password') }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || 'login_failed');
      window.location.assign(basePath);
    } catch (error) {
      status.textContent = window.OsintUk.error(error);
      button.disabled = false;
      button.classList.remove('loading');
    }
  });
})();
