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

  const mountPeriodPreset = (mountNode) => {
    if (!(mountNode instanceof HTMLElement) || mountNode.dataset.islandMounted === '1') return;

    const props = parseProps(mountNode.getAttribute('data-island-props'));
    const formSelector = String(props && props.formSelector ? props.formSelector : '').trim();
    const selectSelector = String(props && props.selectSelector ? props.selectSelector : '').trim();
    if (!selectSelector) return;

    const explicitOptions = Array.isArray(props && props.options) ? props.options : [];
    const activeFallback = String(props && props.active ? props.active : '').trim();
    const submitOnPick = toBool(props && props.submitOnPick, true);

    const resolveSelect = () => document.querySelector(selectSelector);
    const resolveForm = () => {
      if (formSelector) {
        const explicitForm = document.querySelector(formSelector);
        if (explicitForm instanceof HTMLFormElement) return explicitForm;
      }
      const select = resolveSelect();
      if (select && select.closest) {
        const parentForm = select.closest('form');
        if (parentForm instanceof HTMLFormElement) return parentForm;
      }
      return null;
    };

    const readDomOptions = () => {
      const select = resolveSelect();
      if (!(select instanceof HTMLSelectElement)) return [];
      return Array.from(select.options || [])
        .map((item) => ({
          key: String(item && item.value ? item.value : '').trim(),
          label: String(item && item.textContent ? item.textContent : '').trim(),
        }))
        .filter((item) => item.key && item.label);
    };

    const options = explicitOptions.length
      ? explicitOptions
          .map((item) => ({
            key: String(item && item.key ? item.key : '').trim(),
            label: String(item && item.label ? item.label : item && item.key ? item.key : '').trim(),
          }))
          .filter((item) => item.key && item.label)
      : readDomOptions();
    if (!options.length) return;

    const root = document.createElement('div');
    root.className = 'insights-period-presets';
    root.setAttribute('role', 'group');
    root.setAttribute('aria-label', 'Period presets');

    const buttonsByKey = new Map();
    options.forEach((item) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'btn btn-sm island-period-btn';
      button.textContent = item.label;
      button.dataset.key = item.key;
      root.appendChild(button);
      buttonsByKey.set(item.key, button);
    });

    const resolveActiveKey = () => {
      const select = resolveSelect();
      if (select instanceof HTMLSelectElement) {
        return String(select.value || '').trim();
      }
      return activeFallback;
    };

    const syncActive = () => {
      const activeKey = resolveActiveKey();
      buttonsByKey.forEach((button, key) => {
        const isActive = key === activeKey;
        button.classList.toggle('is-active', isActive);
        button.setAttribute('aria-pressed', isActive ? 'true' : 'false');
      });
    };

    const handlePick = (nextKey) => {
      const normalizedNext = String(nextKey || '').trim();
      if (!normalizedNext) return;
      const select = resolveSelect();
      if (select instanceof HTMLSelectElement) {
        if (String(select.value || '').trim() !== normalizedNext) {
          select.value = normalizedNext;
          select.dispatchEvent(new Event('change', { bubbles: true }));
        } else {
          syncActive();
        }
      } else {
        syncActive();
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

    buttonsByKey.forEach((button, key) => {
      button.addEventListener('click', () => handlePick(key));
    });

    const select = resolveSelect();
    if (select instanceof HTMLSelectElement) {
      select.addEventListener('change', syncActive);
    }

    mountNode.replaceChildren(root);
    mountNode.dataset.islandMounted = '1';
    syncActive();
  };

  const mountAll = () => {
    document.querySelectorAll('[data-react-island="insights-period-preset"]').forEach((node) => {
      mountPeriodPreset(node);
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountAll, { once: true });
  } else {
    mountAll();
  }
})();

