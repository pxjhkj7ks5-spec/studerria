(() => {
  const body = document.body;
  const button = document.querySelector('[data-briefcase-button]');
  const label = document.querySelector('[data-briefcase-label]');
  const status = document.querySelector('[data-briefcase-status]');
  const message = document.querySelector('[data-briefcase-message]');

  if (!(body instanceof HTMLElement) || !(button instanceof HTMLButtonElement)) {
    return;
  }

  const stages = {
    standby: {
      className: '',
      label: 'Нажать кнопку',
      status: 'Standby',
      message: 'Система ждёт одного нажатия.',
    },
    arming: {
      className: 'is-arming',
      label: 'Подготовка',
      status: 'Arming',
      message: 'Мягкая подсветка поднята. Сцена вот-вот сменится.',
    },
    launch: {
      className: 'is-launching',
      label: 'Перезапустить',
      status: 'Launch',
      message: 'Визуальный сценарий активен. Никаких реальных действий.',
    },
  };

  let stageResetTimer = 0;
  let launchTimer = 0;
  let currentStage = 'standby';

  function applyStage(stageName) {
    const stage = stages[stageName] || stages.standby;
    body.classList.remove('is-arming', 'is-launching');
    if (stage.className) {
      body.classList.add(stage.className);
    }
    currentStage = stageName;
    body.dataset.briefcaseStage = stageName;
    button.setAttribute('aria-pressed', stageName !== 'standby' ? 'true' : 'false');
    if (label instanceof HTMLElement) {
      label.textContent = stage.label;
    }
    if (status instanceof HTMLElement) {
      status.textContent = stage.status;
    }
    if (message instanceof HTMLElement) {
      message.textContent = stage.message;
    }
  }

  function clearTimers() {
    window.clearTimeout(stageResetTimer);
    window.clearTimeout(launchTimer);
  }

  function triggerSequence() {
    clearTimers();
    if (currentStage === 'launch') {
      applyStage('standby');
      return;
    }
    applyStage('arming');
    launchTimer = window.setTimeout(() => {
      applyStage('launch');
    }, 760);
    stageResetTimer = window.setTimeout(() => {
      applyStage('standby');
    }, 4200);
  }

  button.addEventListener('click', triggerSequence);
  button.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && currentStage !== 'standby') {
      event.preventDefault();
      clearTimers();
      applyStage('standby');
    }
  });

  applyStage('standby');
})();
