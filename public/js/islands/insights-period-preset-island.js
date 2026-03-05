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

  islands.register('insights-period-preset', ({ React, props }) => {
    if (!React || typeof React.createElement !== 'function') {
      return null;
    }

    const useEffect = React.useEffect;
    const useMemo = React.useMemo;
    const useState = React.useState;

    const formSelector = String(props && props.formSelector ? props.formSelector : '').trim();
    const selectSelector = String(props && props.selectSelector ? props.selectSelector : '').trim();
    if (!selectSelector) return null;

    const explicitOptions = Array.isArray(props && props.options) ? props.options : [];
    const activeFallback = String(props && props.active ? props.active : '').trim();
    const submitOnPick = toBool(props && props.submitOnPick, true);

    const resolveSelect = () => document.querySelector(selectSelector);
    const resolveForm = () => {
      if (formSelector) {
        const form = document.querySelector(formSelector);
        if (form instanceof HTMLFormElement) return form;
      }
      const select = resolveSelect();
      if (select && select.closest) {
        const parentForm = select.closest('form');
        if (parentForm instanceof HTMLFormElement) return parentForm;
      }
      return null;
    };

    const readOptionsFromDom = () => {
      const select = resolveSelect();
      if (!(select instanceof HTMLSelectElement)) return [];
      return Array.from(select.options || [])
        .map((item) => ({
          key: String(item && item.value ? item.value : '').trim(),
          label: String(item && item.textContent ? item.textContent : '').trim(),
        }))
        .filter((item) => item.key && item.label);
    };

    const options = useMemo(() => {
      const normalizedExplicit = explicitOptions
        .map((item) => ({
          key: String(item && item.key ? item.key : '').trim(),
          label: String(item && item.label ? item.label : item && item.key ? item.key : '').trim(),
        }))
        .filter((item) => item.key && item.label);
      if (normalizedExplicit.length) {
        return normalizedExplicit;
      }
      return readOptionsFromDom();
    }, [props]);

    const readActive = () => {
      const select = resolveSelect();
      if (select instanceof HTMLSelectElement) {
        return String(select.value || '').trim();
      }
      return activeFallback;
    };

    const [activeKey, setActiveKey] = useState(() => readActive() || activeFallback);

    useEffect(() => {
      const select = resolveSelect();
      if (!(select instanceof HTMLSelectElement)) return undefined;

      const onChange = () => {
        setActiveKey(String(select.value || '').trim());
      };
      select.addEventListener('change', onChange);
      onChange();

      return () => {
        select.removeEventListener('change', onChange);
      };
    }, [selectSelector]);

    if (!options.length) {
      return null;
    }

    const handlePick = (nextKey) => {
      const select = resolveSelect();
      const normalizedNext = String(nextKey || '').trim();
      if (!normalizedNext) return;

      if (select instanceof HTMLSelectElement) {
        if (String(select.value || '').trim() !== normalizedNext) {
          select.value = normalizedNext;
          select.dispatchEvent(new Event('change', { bubbles: true }));
        } else {
          setActiveKey(normalizedNext);
        }
      } else {
        setActiveKey(normalizedNext);
      }

      if (!submitOnPick) return;
      const form = resolveForm();
      if (!(form instanceof HTMLFormElement)) return;
      if (typeof form.requestSubmit === 'function') {
        form.requestSubmit();
      } else {
        form.submit();
      }
    };

    return React.createElement(
      'div',
      { className: 'insights-period-presets', role: 'group', 'aria-label': 'Period presets' },
      options.map((item) => {
        const isActive = String(item.key) === String(activeKey);
        return React.createElement(
          'button',
          {
            type: 'button',
            key: `preset-${item.key}`,
            className: `btn btn-sm island-period-btn${isActive ? ' is-active' : ''}`,
            onClick: () => handlePick(item.key),
            'aria-pressed': isActive ? 'true' : 'false',
          },
          item.label
        );
      })
    );
  });
})();

