(function initTeacherSubjectPicker() {
  function getGroupChoices(root, subjectId) {
    return Array.from(root.querySelectorAll(`[data-subject-group-choice="${subjectId}"]`))
      .filter((input) => input instanceof HTMLInputElement);
  }

  function updateSelectedCount(root) {
    const toggles = Array.from(root.querySelectorAll('[data-subject-toggle]'));
    const selectedCount = toggles.filter((toggle) => toggle instanceof HTMLInputElement && toggle.checked).length;
    root.querySelectorAll('[data-teacher-picker-selected-count]').forEach((node) => {
      node.textContent = String(selectedCount);
    });
  }

  function ensureDefaultGroupChoice(choices) {
    if (!Array.isArray(choices) || choices.some((choice) => choice.checked)) return;
    const defaultChoice = choices.find((choice) => choice.dataset.defaultGroup === '1') || choices[0] || null;
    if (defaultChoice) {
      defaultChoice.checked = true;
    }
  }

  function syncCardState(root, toggle) {
    if (!(toggle instanceof HTMLInputElement)) return;
    const subjectId = String(toggle.dataset.subjectToggle || '').trim();
    if (!subjectId) return;
    const card = toggle.closest('[data-teacher-picker-item]');
    if (card instanceof HTMLElement) {
      card.classList.toggle('is-selected', toggle.checked);
    }
    const groupChoices = getGroupChoices(root, subjectId);
    if (!groupChoices.length) return;
    if (!toggle.checked) {
      groupChoices.forEach((choice) => {
        choice.checked = false;
        choice.disabled = true;
      });
      return;
    }
    groupChoices.forEach((choice) => {
      choice.disabled = false;
    });
    ensureDefaultGroupChoice(groupChoices);
  }

  function syncToggleFromGroups(root, choice) {
    if (!(choice instanceof HTMLInputElement)) return;
    const subjectId = String(choice.dataset.subjectGroupChoice || '').trim();
    if (!subjectId) return;
    const toggle = root.querySelector(`[data-subject-toggle="${subjectId}"]`);
    if (!(toggle instanceof HTMLInputElement)) return;
    const groupChoices = getGroupChoices(root, subjectId);
    const hasCheckedGroups = groupChoices.some((item) => item.checked);
    toggle.checked = hasCheckedGroups;
    syncCardState(root, toggle);
  }

  function restoreDisclosureState(container, query) {
    if (!(container instanceof HTMLElement)) return;
    const details = container.matches('details')
      ? container
      : container.querySelector('details');
    if (!(details instanceof HTMLDetailsElement)) return;
    if (query) {
      details.open = true;
      return;
    }
    details.open = details.dataset.initialOpen === '1';
  }

  function updateVisibility(root) {
    const searchInput = root.querySelector('[data-teacher-picker-search]');
    const query = searchInput instanceof HTMLInputElement
      ? searchInput.value.trim().toLowerCase()
      : '';

    const items = Array.from(root.querySelectorAll('[data-teacher-picker-item]'));
    items.forEach((item) => {
      const haystack = String(item.dataset.search || '').toLowerCase();
      const visible = !query || haystack.includes(query);
      item.hidden = !visible;
    });

    const stageSections = Array.from(root.querySelectorAll('[data-teacher-picker-stage]'));
    stageSections.forEach((stage) => {
      const visibleItems = stage.querySelectorAll('[data-teacher-picker-item]:not([hidden])').length;
      stage.hidden = visibleItems < 1;
      restoreDisclosureState(stage, query && visibleItems > 0 ? query : '');
    });

    const trackSections = Array.from(root.querySelectorAll('[data-teacher-picker-track]'));
    trackSections.forEach((track) => {
      const visibleItems = track.querySelectorAll('[data-teacher-picker-item]:not([hidden])').length;
      track.hidden = visibleItems < 1;
      restoreDisclosureState(track, query && visibleItems > 0 ? query : '');
    });

    const searchEmpty = root.querySelector('[data-teacher-picker-search-empty]');
    if (searchEmpty instanceof HTMLElement) {
      const hasVisibleItems = root.querySelector('[data-teacher-picker-item]:not([hidden])');
      searchEmpty.hidden = Boolean(hasVisibleItems) || !query;
    }
  }

  document.querySelectorAll('[data-teacher-picker-root]').forEach((root) => {
    const searchInput = root.querySelector('[data-teacher-picker-search]');
    if (searchInput instanceof HTMLInputElement) {
      searchInput.addEventListener('input', () => updateVisibility(root));
    }

    root.querySelectorAll('[data-subject-toggle]').forEach((toggle) => {
      syncCardState(root, toggle);
      toggle.addEventListener('change', () => {
        syncCardState(root, toggle);
        updateSelectedCount(root);
      });
    });

    root.querySelectorAll('[data-subject-group-choice]').forEach((choice) => {
      if (!(choice instanceof HTMLInputElement)) return;
      choice.addEventListener('change', () => {
        syncToggleFromGroups(root, choice);
        updateSelectedCount(root);
      });
    });

    updateSelectedCount(root);
    updateVisibility(root);
  });
})();
