(() => {
  const registry = new Map();
  const mounted = new WeakMap();

  function parseProps(rawValue) {
    if (!rawValue || typeof rawValue !== 'string') {
      return {};
    }
    try {
      const parsed = JSON.parse(rawValue);
      return parsed && typeof parsed === 'object' ? parsed : {};
    } catch (_error) {
      return {};
    }
  }

  function mountNode(node) {
    if (!(node instanceof HTMLElement)) {
      return;
    }
    if (mounted.has(node)) {
      return;
    }

    const islandName = String(node.getAttribute('data-react-island') || '').trim();
    if (!islandName) {
      return;
    }

    const renderFn = registry.get(islandName);
    if (typeof renderFn !== 'function') {
      return;
    }

    if (!window.React || !window.ReactDOM) {
      return;
    }

    const props = parseProps(node.getAttribute('data-island-props'));
    const element = renderFn({
      React: window.React,
      props,
      element: node,
    });

    if (!element) {
      return;
    }

    if (typeof window.ReactDOM.createRoot === 'function') {
      const root = window.ReactDOM.createRoot(node);
      root.render(element);
      mounted.set(node, root);
    } else if (typeof window.ReactDOM.render === 'function') {
      window.ReactDOM.render(element, node);
      mounted.set(node, true);
    }
    node.dataset.islandMounted = '1';
  }

  function mountAll(root = document) {
    const scope = root && root.querySelectorAll ? root : document;
    scope.querySelectorAll('[data-react-island]').forEach((node) => mountNode(node));
  }

  window.KMAReactIslands = {
    register(name, renderFn) {
      const key = String(name || '').trim();
      if (!key || typeof renderFn !== 'function') {
        return;
      }
      registry.set(key, renderFn);
      mountAll(document);
    },
    refresh(root) {
      mountAll(root || document);
    },
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => mountAll(document), { once: true });
  } else {
    mountAll(document);
  }
})();
