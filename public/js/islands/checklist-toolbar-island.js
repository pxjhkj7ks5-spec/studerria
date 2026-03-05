(() => {
  const islands = window.KMAReactIslands;
  if (!islands || typeof islands.register !== 'function') {
    return;
  }

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

  islands.register('checklist-toolbar', ({ React, props }) => {
    if (!React || typeof React.createElement !== 'function') {
      return null;
    }

    const useEffect = React.useEffect;
    const useMemo = React.useMemo;
    const useState = React.useState;

    const targetSelector = String(props && props.targetSelector ? props.targetSelector : '').trim();
    if (!targetSelector) return null;

    const checkboxSelector = String(props && props.checkboxSelector
      ? props.checkboxSelector
      : 'input[type="checkbox"]').trim();
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
      return Array.from(target.querySelectorAll(checkboxSelector)).filter((node) => (
        node instanceof HTMLInputElement
      ));
    };
    const collectRows = () => {
      const target = resolveTarget();
      if (!(target instanceof HTMLElement) || !rowSelector) return [];
      return Array.from(target.querySelectorAll(rowSelector)).filter((node) => node instanceof HTMLElement);
    };
    const readStats = () => {
      const checkboxes = collectCheckboxes();
      const available = checkboxes.filter((checkbox) => !checkbox.disabled);
      const checked = available.filter((checkbox) => checkbox.checked);
      return {
        total: available.length,
        checked: checked.length,
      };
    };

    const [stats, setStats] = useState(() => readStats());
    const [query, setQuery] = useState('');

    const syncStats = () => {
      setStats(readStats());
    };

    useEffect(() => {
      const target = resolveTarget();
      if (!(target instanceof HTMLElement)) return undefined;

      const onChange = (event) => {
        if (event && event.target && event.target.matches && event.target.matches(checkboxSelector)) {
          syncStats();
        }
      };
      target.addEventListener('change', onChange);
      syncStats();

      const observer = new MutationObserver(() => {
        syncStats();
      });
      observer.observe(target, { childList: true, subtree: true });

      return () => {
        target.removeEventListener('change', onChange);
        observer.disconnect();
      };
    }, [targetSelector, checkboxSelector]);

    useEffect(() => {
      if (!searchEnabled) return;
      const needle = String(query || '').trim().toLowerCase();
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
    }, [query, searchEnabled, targetSelector, rowSelector, rowTextSelector]);

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
      syncStats();
    };

    const counterLabel = useMemo(() => {
      if (!stats.total) return `${labels.selected}: 0`;
      return `${labels.selected}: ${stats.checked}/${stats.total}`;
    }, [stats, labels.selected]);

    return React.createElement(
      'div',
      { className: 'island-toolbar-shell', role: 'group', 'aria-label': 'Checklist toolbar' },
      searchEnabled
        ? React.createElement('input', {
          type: 'search',
          className: 'form-control form-control-sm island-toolbar-search',
          placeholder: searchPlaceholder,
          value: query,
          onChange: (event) => setQuery(String(event && event.target ? event.target.value : '')),
        })
        : null,
      React.createElement(
        'button',
        {
          type: 'button',
          className: 'btn btn-sm island-toolbar-btn',
          onClick: () => mutate('all'),
          disabled: stats.total < 1 || stats.checked >= stats.total,
        },
        labels.all
      ),
      React.createElement(
        'button',
        {
          type: 'button',
          className: 'btn btn-sm island-toolbar-btn',
          onClick: () => mutate('none'),
          disabled: stats.total < 1 || stats.checked < 1,
        },
        labels.none
      ),
      React.createElement(
        'button',
        {
          type: 'button',
          className: 'btn btn-sm island-toolbar-btn',
          onClick: () => mutate('invert'),
          disabled: stats.total < 1,
        },
        labels.invert
      ),
      React.createElement('span', { className: 'island-toolbar-counter' }, counterLabel)
    );
  });
})();
