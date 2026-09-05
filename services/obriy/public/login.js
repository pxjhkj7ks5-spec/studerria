const configuredBase = document.querySelector('meta[name="app-base"]')?.content ?? '/obriy';
const base = /^\/[a-zA-Z0-9/_-]*$/.test(configuredBase) ? configuredBase.replace(/\/$/, '') : '/obriy';
const form = document.getElementById('login-form');
const input = document.getElementById('access-token');
const toggle = document.getElementById('show-key-button');
const submit = document.getElementById('login-button');
const errorElement = document.getElementById('login-error');
let submitting = false;

function hideKey() {
  input.type = 'password';
  toggle.textContent = 'Показати';
  toggle.setAttribute('aria-pressed', 'false');
  toggle.setAttribute('aria-label', 'Показати ключ доступу');
}

function clearKey() { input.value = ''; hideKey(); }

toggle.addEventListener('click', () => {
  if (input.type === 'text') { hideKey(); return; }
  input.type = 'text';
  toggle.textContent = 'Сховати';
  toggle.setAttribute('aria-pressed', 'true');
  toggle.setAttribute('aria-label', 'Приховати ключ доступу');
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (submitting) return;
  submitting = true;
  submit.disabled = true;
  toggle.disabled = true;
  submit.textContent = 'Входимо…';
  errorElement.hidden = true;
  errorElement.textContent = '';
  hideKey();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(`${base}/api/v1/session`, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ token: input.value.trim() }),
    });
    if (!response.ok) {
      let message = response.status === 401 ? 'Ключ доступу не підійшов. Спробуйте ще раз.' : response.status === 429 ? 'Забагато спроб входу. Зачекайте й спробуйте пізніше.' : 'Не вдалося увійти. Спробуйте пізніше.';
      if (response.status >= 400 && response.status < 500 && response.headers.get('content-type')?.includes('application/json')) {
        try { const payload = await response.json(); if (typeof payload?.error === 'string' && payload.error.length > 0 && payload.error.length <= 300) message = payload.error.replace(/[\u0000-\u001f\u007f]/g, ' '); } catch { /* Keep the status message for malformed responses. */ }
      }
      throw new Error(message);
    }
    clearKey();
    window.location.replace(`${base}/`);
  } catch (error) {
    clearKey();
    errorElement.textContent = error.name === 'AbortError' ? 'Сервер не відповідає вчасно. Спробуйте ще раз.' : error instanceof TypeError ? 'Немає з’єднання із сервером. Перевірте мережу та повторіть спробу.' : error.message;
    errorElement.hidden = false;
    input.focus();
    submitting = false;
    submit.disabled = false;
    toggle.disabled = false;
    submit.textContent = 'Увійти';
  } finally { clearTimeout(timeout); }
});

window.addEventListener('pagehide', clearKey);
window.addEventListener('pageshow', (event) => { if (event.persisted) window.location.reload(); });
