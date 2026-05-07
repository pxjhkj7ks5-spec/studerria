(() => {
  const root = document.querySelector('[data-mb-app]');
  if (!root) return;

  const loginScreen = root.querySelector('[data-login-screen]');
  const appScreen = root.querySelector('[data-app-screen]');
  const loginCard = root.querySelector('.mb-login-card');
  const loginForm = root.querySelector('[data-login-form]');
  const loginError = root.querySelector('[data-login-error]');
  const passwordInput = root.querySelector('[data-password-input]');
  const logoutButton = root.querySelector('[data-logout]');
  const currentAvatar = root.querySelector('[data-current-avatar]');
  const authorAvatar = root.querySelector('[data-author-avatar]');
  const avatarPreview = root.querySelector('[data-avatar-preview]');
  const avatarInput = root.querySelector('[data-avatar-input]');
  const avatarForm = root.querySelector('[data-avatar-form]');
  const messageForm = root.querySelector('[data-message-form]');
  const messageInput = root.querySelector('[data-message-input]');
  const messageText = root.querySelector('[data-message-text]');
  const messageCard = root.querySelector('[data-message-card]');
  const noteDate = root.querySelector('[data-note-date]');
  const moodBadge = root.querySelector('[data-mood-badge]');
  const vibeOptions = Array.from(root.querySelectorAll('[data-vibe]'));
  const randomVibeButton = root.querySelector('[data-random-vibe]');
  const reactionButtons = Array.from(root.querySelectorAll('[data-reactions] button'));
  const toast = root.querySelector('[data-toast]');

  const emptyMessage = 'сьогодні тут ще тихо... але, здається, скоро щось зʼявиться 🥹';
  const vibes = ['soft-glow', 'clouds', 'sparkles', 'tiny-faces'];
  const moods = ['soft day', 'main character mood', 'cloudy but cute', 'tiny magic'];
  let state = null;
  let toastTimer = 0;

  function todayLabel() {
    try {
      return new Intl.DateTimeFormat('uk-UA', {
        day: 'numeric',
        month: 'long',
      }).format(new Date());
    } catch (_error) {
      return 'сьогодні';
    }
  }

  function moodForToday() {
    const dayKey = Math.floor(Date.now() / 86400000);
    return moods[dayKey % moods.length];
  }

  function setScreens(isLoggedIn) {
    loginScreen?.classList.toggle('is-hidden', isLoggedIn);
    appScreen?.classList.toggle('is-hidden', !isLoggedIn);
  }

  function initialsFor(profile) {
    const raw = String(profile?.displayName || '').trim();
    if (!raw) return '✨';
    const letters = raw
      .split(/\s+/)
      .map((part) => part[0])
      .join('')
      .slice(0, 2)
      .toUpperCase();
    return letters || '✨';
  }

  function renderAvatar(target, profile) {
    if (!(target instanceof HTMLElement)) return;
    const avatarUrl = String(profile?.avatarUrl || '').trim();
    target.textContent = '';
    target.style.removeProperty('background-image');

    if (avatarUrl) {
      const image = document.createElement('img');
      image.src = avatarUrl;
      image.alt = '';
      image.loading = 'lazy';
      image.referrerPolicy = 'no-referrer';
      image.addEventListener('error', () => {
        image.remove();
        target.textContent = initialsFor(profile);
      }, { once: true });
      target.appendChild(image);
      return;
    }

    target.textContent = initialsFor(profile);
  }

  function setVibe(vibe) {
    const next = vibes.includes(vibe) ? vibe : 'soft-glow';
    messageCard?.setAttribute('data-vibe', next);
    vibeOptions.forEach((button) => {
      button.classList.toggle('is-active', button.getAttribute('data-vibe') === next);
    });
  }

  function showToast(text) {
    if (!(toast instanceof HTMLElement)) return;
    window.clearTimeout(toastTimer);
    toast.textContent = text;
    toast.classList.add('is-visible');
    toastTimer = window.setTimeout(() => {
      toast.classList.remove('is-visible');
    }, 2200);
  }

  async function requestJson(url, options = {}) {
    const response = await fetch(url, {
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
      ...options,
    });
    let payload = {};
    try {
      payload = await response.json();
    } catch (_error) {
      payload = {};
    }
    if (!response.ok || payload.ok === false) {
      const error = new Error(payload.error || 'request_failed');
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  function renderReaction() {
    const key = state?.currentUser?.displayName ? `mb:reaction:${state.currentUser.displayName}` : 'mb:reaction';
    let active = '';
    try {
      active = window.localStorage.getItem(key) || '';
    } catch (_error) {
      active = '';
    }
    reactionButtons.forEach((button) => {
      button.classList.toggle('is-active', button.textContent === active);
    });
  }

  function render(nextState) {
    state = nextState;
    if (!state || !state.authenticated) {
      setScreens(false);
      return;
    }

    setScreens(true);
    const current = state.currentUser || {};
    const author = state.otherUser || {};
    const received = state.receivedMessage || {};
    const draft = state.draftForOther || {};

    renderAvatar(currentAvatar, current);
    renderAvatar(authorAvatar, author);
    renderAvatar(avatarPreview, current);
    if (avatarInput) avatarInput.value = current.avatarUrl || '';
    if (messageInput) messageInput.value = draft.text || '';
    if (messageText) messageText.textContent = received.text || emptyMessage;
    if (noteDate) noteDate.textContent = received.updatedAtLabel || todayLabel();
    if (moodBadge) moodBadge.textContent = state.mood || moodForToday();
    setVibe(draft.animationType || received.animationType || 'soft-glow');
    renderReaction();
  }

  async function loadState() {
    try {
      const payload = await requestJson('/mb/api/state');
      render(payload);
    } catch (_error) {
      setScreens(false);
    }
  }

  loginForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (loginError) loginError.textContent = '';
    const password = String(passwordInput?.value || '');
    try {
      const payload = await requestJson('/mb/login', {
        method: 'POST',
        body: JSON.stringify({ password }),
      });
      if (passwordInput) passwordInput.value = '';
      try {
        window.localStorage.setItem('mb:last-login', String(Date.now()));
      } catch (_error) {}
      render(payload);
    } catch (_error) {
      if (loginError) loginError.textContent = 'не той ключик 🥹';
      loginCard?.classList.remove('is-shaking');
      window.requestAnimationFrame(() => {
        loginCard?.classList.add('is-shaking');
      });
      passwordInput?.focus();
    }
  });

  logoutButton?.addEventListener('click', async () => {
    try {
      await requestJson('/mb/logout', { method: 'POST', body: '{}' });
    } catch (_error) {}
    state = null;
    setScreens(false);
  });

  vibeOptions.forEach((button) => {
    button.addEventListener('click', () => {
      setVibe(button.getAttribute('data-vibe'));
    });
  });

  randomVibeButton?.addEventListener('click', () => {
    const current = messageCard?.getAttribute('data-vibe') || 'soft-glow';
    const index = vibes.indexOf(current);
    setVibe(vibes[(index + 1 + vibes.length) % vibes.length]);
  });

  messageForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const text = String(messageInput?.value || '');
    const animationType = messageCard?.getAttribute('data-vibe') || 'soft-glow';
    try {
      const payload = await requestJson('/mb/api/message', {
        method: 'POST',
        body: JSON.stringify({ text, animationType }),
      });
      render(payload);
      showToast('відправлено 🫶');
    } catch (_error) {
      showToast('не вийшло зберегти 🥹');
    }
  });

  avatarInput?.addEventListener('input', () => {
    renderAvatar(avatarPreview, {
      ...(state?.currentUser || {}),
      avatarUrl: avatarInput.value,
    });
  });

  avatarForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      const payload = await requestJson('/mb/api/avatar', {
        method: 'POST',
        body: JSON.stringify({ avatarUrl: avatarInput?.value || '' }),
      });
      render(payload);
      showToast('аватар збережено ✨');
    } catch (_error) {
      showToast('цей URL не схожий на картинку 🥹');
    }
  });

  reactionButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const key = state?.currentUser?.displayName ? `mb:reaction:${state.currentUser.displayName}` : 'mb:reaction';
      try {
        window.localStorage.setItem(key, button.textContent || '');
      } catch (_error) {}
      renderReaction();
      showToast(`${button.textContent} збережено`);
    });
  });

  if (noteDate) noteDate.textContent = todayLabel();
  if (moodBadge) moodBadge.textContent = moodForToday();
  loadState();
})();
