(() => {
  const form = document.querySelector('[data-reg-groups-form]');
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  const rows = Array.from(form.querySelectorAll('[data-reg-groups-row]')).filter(
    (row) => row instanceof HTMLElement
  );
  if (!rows.length) {
    return;
  }

  const config = Object.assign(
    {
      statusSelected: 'Selected',
      statusPending: 'Needs selection',
      statusSkipped: 'Skipped',
      remaining: 'Remaining',
      allSet: 'Everything is ready.',
      submitHintIncomplete: 'Choose a group for every active subject.',
      missingHintPrefix: 'Choose groups for',
      filterEmpty: 'All active subjects are already filled in.',
      selectedSuffix: 'selected',
    },
    window.__registerGroupsConfig || {}
  );

  const selectedOutputs = Array.from(document.querySelectorAll('[data-reg-groups-selected]'));
  const totalOutputs = Array.from(document.querySelectorAll('[data-reg-groups-total]'));
  const remainingOutputs = Array.from(document.querySelectorAll('[data-reg-groups-remaining], [data-reg-groups-sticky-remaining]'));
  const missingOutputs = Array.from(document.querySelectorAll('[data-reg-groups-missing]'));
  const submitHintOutputs = Array.from(document.querySelectorAll('[data-reg-groups-submit-hint]'));
  const submitButtons = Array.from(document.querySelectorAll('[data-reg-groups-submit]'));
  const progressbar = document.querySelector('[data-reg-groups-progress]');
  const progressFill = document.querySelector('[data-reg-groups-progress-bar]');
  const filterInput = document.querySelector('[data-reg-groups-filter]');
  const emptyState = form.querySelector('[data-reg-groups-empty]');
  const quickButtons = Array.from(document.querySelectorAll('[data-reg-groups-quick-group]'));
  const resetButton = document.querySelector('[data-reg-groups-reset]');

  const selectedGroupsBySubject = {};
  window.selectedGroupsBySubject = selectedGroupsBySubject;

  const getHiddenInput = (row) => row.querySelector('[data-reg-groups-input]');
  const getOptoutInput = (row) => row.querySelector('[data-reg-groups-optout]');
  const getButtons = (row) => Array.from(row.querySelectorAll('[data-reg-groups-group]'));
  const getSubjectId = (row) => String(row.dataset.subjectId || '').trim();
  const getSubjectName = (row) => String(row.dataset.subjectName || '').trim();
  const getGroupCount = (row) => Number(row.dataset.groupCount || 0);
  const getStatusLabel = (row) => row.querySelector('[data-reg-groups-status-label]');

  const setNodeText = (nodes, text) => {
    nodes.forEach((node) => {
      if (node instanceof HTMLElement) {
        node.textContent = text;
      }
    });
  };

  const setOptionalVisibility = (nodes, text) => {
    nodes.forEach((node) => {
      if (!(node instanceof HTMLElement)) {
        return;
      }

      const nextText = String(text || '').trim();
      node.textContent = nextText;
      node.hidden = nextText.length === 0;
    });
  };

  const readSelectedGroup = (row) => {
    const input = getHiddenInput(row);
    const groupCount = getGroupCount(row);
    if (!(input instanceof HTMLInputElement)) {
      return null;
    }

    const value = Number(input.value);
    if (!Number.isInteger(value) || value < 1 || value > groupCount) {
      input.value = '';
      return null;
    }

    return value;
  };

  const isOptedOut = (row) => {
    const optout = getOptoutInput(row);
    return optout instanceof HTMLInputElement ? optout.checked : false;
  };

  const updateStateForRow = (row, selectedGroup) => {
    const subjectId = getSubjectId(row);
    if (!subjectId) {
      return;
    }

    if (selectedGroup) {
      selectedGroupsBySubject[subjectId] = selectedGroup;
      return;
    }

    delete selectedGroupsBySubject[subjectId];
  };

  const setSelectedGroup = (row, groupNumber) => {
    const input = getHiddenInput(row);
    if (!(input instanceof HTMLInputElement)) {
      return;
    }

    const groupCount = getGroupCount(row);
    const normalized = Number(groupNumber);
    const nextValue = Number.isInteger(normalized) && normalized >= 1 && normalized <= groupCount
      ? normalized
      : null;

    input.value = nextValue ? String(nextValue) : '';
    updateStateForRow(row, nextValue);
  };

  const syncButtons = (row, selectedGroup, optedOut) => {
    getButtons(row).forEach((button) => {
      if (!(button instanceof HTMLButtonElement)) {
        return;
      }

      const buttonGroup = Number(button.dataset.regGroupsGroup || button.getAttribute('data-reg-groups-group'));
      const isActive = !optedOut && selectedGroup === buttonGroup;
      button.classList.toggle('is-active', isActive);
      button.setAttribute('aria-pressed', isActive ? 'true' : 'false');
      button.disabled = optedOut;
      button.setAttribute('aria-disabled', optedOut ? 'true' : 'false');
    });
  };

  const syncRow = (row) => {
    const selectedGroup = isOptedOut(row) ? null : readSelectedGroup(row);
    const optedOut = isOptedOut(row);
    const statusLabel = getStatusLabel(row);

    if (optedOut) {
      setSelectedGroup(row, null);
    } else {
      updateStateForRow(row, selectedGroup);
    }

    syncButtons(row, optedOut ? null : selectedGroup, optedOut);
    row.dataset.optedOut = optedOut ? '1' : '0';
    row.classList.toggle('is-pending', !optedOut && !selectedGroup);
    row.classList.toggle('is-opted-out', optedOut);

    if (statusLabel instanceof HTMLElement) {
      statusLabel.textContent = optedOut
        ? config.statusSkipped
        : selectedGroup
          ? config.statusSelected
          : config.statusPending;
    }
  };

  const formatMissingNames = (missingRows) => {
    const names = missingRows.map(getSubjectName).filter(Boolean);
    if (!names.length) {
      return '';
    }

    if (names.length <= 3) {
      return names.join(', ');
    }

    return `${names.slice(0, 3).join(', ')} +${names.length - 3}`;
  };

  const computeProgress = () => {
    const activeRows = rows.filter((row) => !isOptedOut(row));
    const selectedRows = activeRows.filter((row) => Boolean(readSelectedGroup(row)));
    const missingRows = activeRows.filter((row) => !readSelectedGroup(row));

    return {
      activeRows,
      selectedRows,
      missingRows,
      selectedCount: selectedRows.length,
      totalCount: activeRows.length,
    };
  };

  const syncQuickButtons = (progressState) => {
    const { activeRows } = progressState;
    const referenceGroup =
      activeRows.length > 0 &&
      activeRows.every((row) => {
        const selectedGroup = readSelectedGroup(row);
        return Boolean(selectedGroup);
      })
        ? readSelectedGroup(activeRows[0])
        : null;

    quickButtons.forEach((button) => {
      if (!(button instanceof HTMLButtonElement)) {
        return;
      }

      const quickGroup = Number(button.dataset.regGroupsQuickGroup || button.getAttribute('data-reg-groups-quick-group'));
      const isActive = Boolean(referenceGroup) && activeRows.every((row) => readSelectedGroup(row) === quickGroup);
      button.classList.toggle('is-active', isActive);
      button.setAttribute('aria-pressed', isActive ? 'true' : 'false');
    });
  };

  const syncFilter = (progressState) => {
    const onlyPending = filterInput instanceof HTMLInputElement && filterInput.checked;
    let visibleCount = 0;

    rows.forEach((row) => {
      const shouldHide = onlyPending && (isOptedOut(row) || Boolean(readSelectedGroup(row)));
      row.hidden = shouldHide;
      row.setAttribute('aria-hidden', shouldHide ? 'true' : 'false');
      if (!shouldHide) {
        visibleCount += 1;
      }
    });

    if (emptyState instanceof HTMLElement) {
      emptyState.hidden = !(onlyPending && visibleCount === 0);
      emptyState.textContent = config.filterEmpty;
    }

    return progressState;
  };

  const updateUI = () => {
    rows.forEach(syncRow);

    const progressState = computeProgress();
    const { selectedCount, totalCount, missingRows } = progressState;
    const missingCount = missingRows.length;
    const remainingText = missingCount > 0
      ? `${config.remaining}: ${missingCount}`
      : config.allSet;
    const missingText = missingCount > 0
      ? `${config.missingHintPrefix}: ${formatMissingNames(missingRows)}`
      : '';
    const submitHint = missingCount > 0 ? config.submitHintIncomplete : '';
    const canSubmit = missingCount === 0;
    const progressPercent = totalCount > 0 ? Math.round((selectedCount / totalCount) * 100) : 100;

    setNodeText(selectedOutputs, String(selectedCount));
    setNodeText(totalOutputs, String(totalCount));
    setNodeText(remainingOutputs, remainingText);
    setOptionalVisibility(missingOutputs, missingText);
    setOptionalVisibility(submitHintOutputs, submitHint);

    submitButtons.forEach((button) => {
      if (!(button instanceof HTMLButtonElement)) {
        return;
      }

      button.disabled = !canSubmit;
      button.title = canSubmit ? '' : submitHint;
    });

    if (progressbar instanceof HTMLElement) {
      progressbar.setAttribute('aria-valuenow', String(selectedCount));
      progressbar.setAttribute('aria-valuemax', String(totalCount));
    }

    if (progressFill instanceof HTMLElement) {
      progressFill.style.width = `${progressPercent}%`;
    }

    syncQuickButtons(progressState);
    syncFilter(progressState);

    return progressState;
  };

  rows.forEach((row) => {
    getButtons(row).forEach((button) => {
      if (!(button instanceof HTMLButtonElement)) {
        return;
      }

      button.addEventListener('click', () => {
        if (button.disabled) {
          return;
        }

        const nextGroup = Number(button.dataset.regGroupsGroup || button.getAttribute('data-reg-groups-group'));
        setSelectedGroup(row, nextGroup);
        updateUI();
      });
    });

    const optout = getOptoutInput(row);
    if (optout instanceof HTMLInputElement) {
      optout.addEventListener('change', () => {
        if (optout.checked) {
          setSelectedGroup(row, null);
        }
        updateUI();
      });
    }
  });

  if (filterInput instanceof HTMLInputElement) {
    filterInput.addEventListener('change', () => {
      updateUI();
    });
  }

  quickButtons.forEach((button) => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }

    button.addEventListener('click', () => {
      const quickGroup = Number(button.dataset.regGroupsQuickGroup || button.getAttribute('data-reg-groups-quick-group'));
      rows.forEach((row) => {
        if (isOptedOut(row)) {
          return;
        }

        const groupCount = getGroupCount(row);
        if (Number.isInteger(quickGroup) && quickGroup >= 1 && quickGroup <= groupCount) {
          setSelectedGroup(row, quickGroup);
          return;
        }

        setSelectedGroup(row, null);
      });
      updateUI();
    });
  });

  if (resetButton instanceof HTMLButtonElement) {
    resetButton.addEventListener('click', () => {
      rows.forEach((row) => {
        if (isOptedOut(row)) {
          return;
        }

        setSelectedGroup(row, null);
      });
      updateUI();
    });
  }

  form.addEventListener('submit', (event) => {
    const progressState = updateUI();
    if (progressState.missingRows.length === 0) {
      return;
    }

    event.preventDefault();

    const [firstMissingRow] = progressState.missingRows;
    if (!(firstMissingRow instanceof HTMLElement)) {
      return;
    }

    firstMissingRow.hidden = false;
    firstMissingRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
    const firstButton = firstMissingRow.querySelector('[data-reg-groups-group]');
    if (firstButton instanceof HTMLButtonElement) {
      firstButton.focus({ preventScroll: true });
    }
  });

  updateUI();
})();
