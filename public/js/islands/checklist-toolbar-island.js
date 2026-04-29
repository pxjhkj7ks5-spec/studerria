(() => {
  const toBool = (value, fallback = false) => {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') return value > 0;
    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();
      if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
      if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
    }
    return fallback;
  };

  const parseProps = (rawValue) => {
    if (!rawValue || typeof rawValue !== 'string') return {};
    try {
      const parsed = JSON.parse(rawValue);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (_error) {
      return {};
    }
  };

  const mountChecklistToolbar = (mountNode) => {
    if (!(mountNode instanceof HTMLElement) || mountNode.dataset.islandMounted === '1') return;

    const props = parseProps(mountNode.getAttribute('data-island-props'));
    const targetSelector = String(props && props.targetSelector ? props.targetSelector : '').trim();
    if (!targetSelector) return;

    const checkboxSelector = String(props && props.checkboxSelector ? props.checkboxSelector : 'input[type="checkbox"]').trim();
    const rowSelector = String(props && props.rowSelector ? props.rowSelector : '[data-checklist-row]').trim();
    const rowTextSelector = String(props && props.rowTextSelector ? props.rowTextSelector : '[data-checklist-text]').trim();
    const searchEnabled = toBool(props && props.searchEnabled, true);
    const searchPlaceholder = String(props && props.searchPlaceholder ? props.searchPlaceholder : 'Search').trim();
    const labels = {
      all: String(props && props.labels && props.labels.all ? props.labels.all : 'All'),
      none: String(props && props.labels && props.labels.none ? props.labels.none : 'None'),
      invert: String(props && props.labels && props.labels.invert ? props.labels.invert : 'Invert'),
      selected: String(props && props.labels && props.labels.selected ? props.labels.selected : 'Selected'),
    };

    const resolveTarget = () => document.querySelector(targetSelector);
    const collectCheckboxes = () => {
      const target = resolveTarget();
      if (!(target instanceof HTMLElement)) return [];
      return Array.from(target.querySelectorAll(checkboxSelector)).filter((node) => node instanceof HTMLInputElement);
    };
    const collectRows = () => {
      const target = resolveTarget();
      if (!(target instanceof HTMLElement) || !rowSelector) return [];
      return Array.from(target.querySelectorAll(rowSelector)).filter((node) => node instanceof HTMLElement);
    };

    const root = document.createElement('div');
    root.className = 'island-toolbar-shell';
    root.setAttribute('role', 'group');
    root.setAttribute('aria-label', 'Checklist toolbar');

    let searchInput = null;
    if (searchEnabled) {
      searchInput = document.createElement('input');
      searchInput.type = 'search';
      searchInput.className = 'form-control form-control-sm island-toolbar-search';
      searchInput.placeholder = searchPlaceholder;
      root.appendChild(searchInput);
    }

    const allButton = document.createElement('button');
    allButton.type = 'button';
    allButton.className = 'btn btn-sm island-toolbar-btn';
    allButton.textContent = labels.all;
    root.appendChild(allButton);

    const noneButton = document.createElement('button');
    noneButton.type = 'button';
    noneButton.className = 'btn btn-sm island-toolbar-btn';
    noneButton.textContent = labels.none;
    root.appendChild(noneButton);

    const invertButton = document.createElement('button');
    invertButton.type = 'button';
    invertButton.className = 'btn btn-sm island-toolbar-btn';
    invertButton.textContent = labels.invert;
    root.appendChild(invertButton);

    const counter = document.createElement('span');
    counter.className = 'island-toolbar-counter';
    root.appendChild(counter);

    const readStats = () => {
      const available = collectCheckboxes().filter((checkbox) => !checkbox.disabled);
      const checked = available.filter((checkbox) => checkbox.checked);
      return { total: available.length, checked: checked.length };
    };

    const applySearch = () => {
      if (!searchInput) return;
      const needle = String(searchInput.value || '').trim().toLowerCase();
      const rows = collectRows();
      rows.forEach((row) => {
        if (!needle) {
          row.hidden = false;
          return;
        }
        const directText = String(row.getAttribute('data-checklist-text') || '').toLowerCase();
        const sourceNode = rowTextSelector ? row.querySelector(rowTextSelector) : null;
        const nestedText = sourceNode ? String(sourceNode.textContent || '').toLowerCase() : '';
        const rawText = directText || nestedText || String(row.textContent || '').toLowerCase();
        row.hidden = !rawText.includes(needle);
      });
    };

    const syncState = () => {
      const stats = readStats();
      counter.textContent = stats.total < 1
        ? `${labels.selected}: 0`
        : `${labels.selected}: ${stats.checked}/${stats.total}`;
      allButton.disabled = stats.total < 1 || stats.checked >= stats.total;
      noneButton.disabled = stats.total < 1 || stats.checked < 1;
      invertButton.disabled = stats.total < 1;
      applySearch();
    };

    const mutate = (mode) => {
      const checkboxes = collectCheckboxes().filter((checkbox) => !checkbox.disabled);
      if (!checkboxes.length) return;
      checkboxes.forEach((checkbox) => {
        let nextChecked = checkbox.checked;
        if (mode === 'all') nextChecked = true;
        if (mode === 'none') nextChecked = false;
        if (mode === 'invert') nextChecked = !checkbox.checked;
        if (nextChecked === checkbox.checked) return;
        checkbox.checked = nextChecked;
        checkbox.dispatchEvent(new Event('change', { bubbles: true }));
      });
      syncState();
    };

    allButton.addEventListener('click', () => mutate('all'));
    noneButton.addEventListener('click', () => mutate('none'));
    invertButton.addEventListener('click', () => mutate('invert'));
    if (searchInput) {
      searchInput.addEventListener('input', applySearch);
    }

    const target = resolveTarget();
    if (target instanceof HTMLElement) {
      const onChange = (event) => {
        if (event && event.target && event.target.matches && event.target.matches(checkboxSelector)) {
          syncState();
        }
      };
      target.addEventListener('change', onChange);
      const observer = new MutationObserver(syncState);
      observer.observe(target, { childList: true, subtree: true });
    }

    mountNode.replaceChildren(root);
    mountNode.dataset.islandMounted = '1';
    syncState();
  };

  const mountAll = () => {
    document.querySelectorAll('[data-react-island="checklist-toolbar"]').forEach((node) => {
      mountChecklistToolbar(node);
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountAll, { once: true });
  } else {
    mountAll();
  }
})();
