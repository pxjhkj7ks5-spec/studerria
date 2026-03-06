(() => {
  const NAV_SELECTOR = '[data-studerria-nav]';
  const ITEM_SELECTOR = '.snav-item--has-children';
  const TRIGGER_SELECTOR = '[data-nav-trigger]';
  const ACTION_SELECTOR = '[data-nav-action]';
  const PANEL_MAP = {
    messages: 'messagesModal',
    'custom-deadlines': 'customDeadlineModal',
  };

  function getHoverMatcher() {
    if (typeof window.matchMedia !== 'function') {
      return null;
    }
    return window.matchMedia('(hover: hover) and (pointer: fine)');
  }

  function getDirectTrigger(item) {
    if (!(item instanceof HTMLElement)) {
      return null;
    }
    return Array.from(item.children).find((child) => child instanceof HTMLElement && child.matches(TRIGGER_SELECTOR)) || null;
  }

  function getDirectPanel(item) {
    if (!(item instanceof HTMLElement)) {
      return null;
    }
    return Array.from(item.children).find((child) => child instanceof HTMLElement && child.classList.contains('snav-menu')) || null;
  }

  function closeNestedItems(item) {
    if (!(item instanceof HTMLElement)) {
      return;
    }
    item.querySelectorAll(ITEM_SELECTOR).forEach((child) => {
      if (child !== item) {
        syncItem(child, false);
      }
    });
  }

  function syncItem(item, open) {
    if (!(item instanceof HTMLElement)) {
      return;
    }
    const isOpen = Boolean(open);
    const trigger = getDirectTrigger(item);
    const panel = getDirectPanel(item);
    const isNested = Boolean(item.parentElement && item.parentElement.closest('.snav-menu'));

    item.classList.toggle('is-open', isOpen);
    item.classList.toggle('is-subopen', isOpen && isNested);

    if (panel) {
      panel.hidden = !isOpen;
    }
    if (trigger) {
      trigger.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      trigger.removeAttribute('data-touch-armed');
    }

    if (!isOpen) {
      closeNestedItems(item);
    }
  }

  function closeSiblings(item) {
    if (!(item instanceof HTMLElement) || !(item.parentElement instanceof HTMLElement)) {
      return;
    }
    Array.from(item.parentElement.children).forEach((sibling) => {
      if (sibling instanceof HTMLElement && sibling !== item && sibling.matches(ITEM_SELECTOR)) {
        syncItem(sibling, false);
      }
    });
  }

  function openItem(item, options = {}) {
    if (!(item instanceof HTMLElement)) {
      return;
    }
    const focusFirst = Boolean(options.focusFirst);
    const parentItem = item.parentElement instanceof HTMLElement
      ? item.parentElement.closest(ITEM_SELECTOR)
      : null;

    if (parentItem) {
      openItem(parentItem);
    }

    closeSiblings(item);
    syncItem(item, true);

    if (focusFirst) {
      const panel = getDirectPanel(item);
      const firstFocusable = panel
        ? panel.querySelector('a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])')
        : null;
      if (firstFocusable instanceof HTMLElement) {
        firstFocusable.focus();
      }
    }
  }

  function closeAll(root) {
    if (!(root instanceof HTMLElement)) {
      return;
    }
    root.querySelectorAll(ITEM_SELECTOR).forEach((item) => {
      syncItem(item, false);
    });
  }

  function focusParentTrigger(item) {
    if (!(item instanceof HTMLElement)) {
      return;
    }
    const parentItem = item.parentElement instanceof HTMLElement
      ? item.parentElement.closest(ITEM_SELECTOR)
      : null;
    if (!(parentItem instanceof HTMLElement)) {
      return;
    }
    const trigger = getDirectTrigger(parentItem);
    if (trigger instanceof HTMLElement) {
      trigger.focus();
    }
  }

  function focusItemTrigger(item) {
    if (!(item instanceof HTMLElement)) {
      return;
    }
    const trigger = getDirectTrigger(item);
    if (trigger instanceof HTMLElement) {
      trigger.focus();
    }
  }

  function getOwningItem(target) {
    if (!(target instanceof Element)) {
      return null;
    }
    return target.closest(ITEM_SELECTOR);
  }

  function openPanelAction(action) {
    const modalId = PANEL_MAP[action];
    if (!modalId || !window.bootstrap || !window.bootstrap.Modal) {
      return false;
    }
    const modal = document.getElementById(modalId);
    if (!(modal instanceof HTMLElement)) {
      return false;
    }
    const instance = window.bootstrap.Modal.getOrCreateInstance(modal);
    instance.show();
    return true;
  }

  function handleActionElement(actionElement, event, root) {
    if (!(actionElement instanceof HTMLElement)) {
      return;
    }
    const action = String(actionElement.dataset.navAction || '').trim();
    if (!action || action === 'theme-toggle') {
      return;
    }

    const currentPath = (window.location.pathname || '/').replace(/\/+$/, '') || '/';
    if (currentPath === '/schedule' && openPanelAction(action)) {
      event.preventDefault();
      closeAll(root);
    }
  }

  function openPanelFromQuery() {
    const currentPath = (window.location.pathname || '/').replace(/\/+$/, '') || '/';
    if (currentPath !== '/schedule') {
      return;
    }

    const url = new URL(window.location.href);
    const panel = String(url.searchParams.get('panel') || '').trim();
    const action = panel === 'messages'
      ? 'messages'
      : (panel === 'deadlines' ? 'custom-deadlines' : '');

    if (!action || !openPanelAction(action)) {
      return;
    }

    url.searchParams.delete('panel');
    const nextSearch = url.searchParams.toString();
    const nextUrl = `${url.pathname}${nextSearch ? `?${nextSearch}` : ''}${url.hash}`;
    window.history.replaceState({}, '', nextUrl);
  }

  function initUnreadIndicators(root) {
    if (!(root instanceof HTMLElement)) {
      return;
    }

    const indicators = Array.from(root.querySelectorAll('[data-message-indicator]'));
    if (!indicators.length) {
      return;
    }

    let requestToken = 0;

    const applyUnreadState = (count) => {
      const unreadCount = Number.isFinite(Number(count)) ? Number(count) : 0;
      const hasUnread = unreadCount > 0;

      indicators.forEach((indicator) => {
        if (!(indicator instanceof HTMLElement)) {
          return;
        }
        indicator.hidden = !hasUnread;
        indicator.toggleAttribute('data-has-unread', hasUnread);
      });
    };

    const fetchUnreadState = async () => {
      const token = ++requestToken;
      try {
        const response = await fetch('/messages.json', {
          credentials: 'same-origin',
          headers: {
            Accept: 'application/json',
          },
        });
        if (!response.ok) {
          return;
        }

        const payload = await response.json();
        if (token !== requestToken) {
          return;
        }

        applyUnreadState(Number(payload && payload.unread_count) || 0);
      } catch (_error) {
        // Keep the last known state on transient failures.
      }
    };

    window.addEventListener('studerria:messages-unread', (event) => {
      const count = Number(event && event.detail && event.detail.count);
      if (!Number.isFinite(count)) {
        return;
      }
      applyUnreadState(count);
    });

    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        fetchUnreadState();
      }
    });

    window.addEventListener('focus', fetchUnreadState);

    fetchUnreadState();
    window.setInterval(fetchUnreadState, 60000);
  }

  function initNav(root) {
    if (!(root instanceof HTMLElement) || root.dataset.navReady === '1') {
      return;
    }
    root.dataset.navReady = '1';

    initUnreadIndicators(root);

    const hoverMatcher = getHoverMatcher();
    let hoverEnabled = hoverMatcher ? hoverMatcher.matches : false;
    let closeTimer = 0;

    const scheduleClose = () => {
      window.clearTimeout(closeTimer);
      closeTimer = window.setTimeout(() => {
        if (!root.matches(':focus-within')) {
          closeAll(root);
        }
      }, 90);
    };

    const cancelClose = () => {
      window.clearTimeout(closeTimer);
    };

    if (hoverMatcher && typeof hoverMatcher.addEventListener === 'function') {
      hoverMatcher.addEventListener('change', (event) => {
        hoverEnabled = event.matches;
        if (!hoverEnabled) {
          closeAll(root);
        }
      });
    }

    root.querySelectorAll(ITEM_SELECTOR).forEach((item) => {
      item.addEventListener('pointerenter', () => {
        if (!hoverEnabled) {
          return;
        }
        cancelClose();
        openItem(item);
      });
    });

    root.addEventListener('pointerleave', () => {
      if (!hoverEnabled) {
        return;
      }
      scheduleClose();
    });

    root.addEventListener('focusin', (event) => {
      cancelClose();
      const owningItem = getOwningItem(event.target);
      if (owningItem) {
        openItem(owningItem);
      }
    });

    root.addEventListener('focusout', () => {
      window.setTimeout(() => {
        if (!root.contains(document.activeElement)) {
          closeAll(root);
        }
      }, 0);
    });

    root.addEventListener('click', (event) => {
      const actionElement = event.target instanceof Element
        ? event.target.closest(ACTION_SELECTOR)
        : null;
      if (actionElement && root.contains(actionElement)) {
        handleActionElement(actionElement, event, root);
      }

      const trigger = event.target instanceof Element
        ? event.target.closest(TRIGGER_SELECTOR)
        : null;
      if (!(trigger instanceof HTMLElement) || !root.contains(trigger)) {
        return;
      }

      const owningItem = getOwningItem(trigger);
      if (!(owningItem instanceof HTMLElement)) {
        return;
      }

      const isButtonTrigger = trigger.tagName === 'BUTTON';
      if (hoverEnabled && !isButtonTrigger) {
        return;
      }

      const isArmed = trigger.getAttribute('data-touch-armed') === '1';
      if (isButtonTrigger) {
        event.preventDefault();
        if (owningItem.classList.contains('is-open')) {
          syncItem(owningItem, false);
        } else {
          openItem(owningItem);
        }
        return;
      }

      if (!isArmed || !owningItem.classList.contains('is-open')) {
        event.preventDefault();
        openItem(owningItem);
        trigger.setAttribute('data-touch-armed', '1');
      } else {
        trigger.removeAttribute('data-touch-armed');
      }
    });

    root.addEventListener('keydown', (event) => {
      const trigger = event.target instanceof Element
        ? event.target.closest(TRIGGER_SELECTOR)
        : null;
      const owningItem = getOwningItem(event.target);

      if (event.key === 'Escape') {
        closeAll(root);
        if (trigger instanceof HTMLElement) {
          trigger.focus();
        }
        return;
      }

      if (!(trigger instanceof HTMLElement) || !(owningItem instanceof HTMLElement)) {
        if (event.key === 'ArrowLeft' && owningItem instanceof HTMLElement) {
          event.preventDefault();
          syncItem(owningItem, false);
          focusItemTrigger(owningItem);
        }
        return;
      }

      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        openItem(owningItem, { focusFirst: true });
        return;
      }

      if (event.key === 'ArrowRight') {
        event.preventDefault();
        openItem(owningItem, { focusFirst: true });
        return;
      }

      if (event.key === 'ArrowLeft') {
        event.preventDefault();
        syncItem(owningItem, false);
        if (owningItem.parentElement instanceof HTMLElement && owningItem.parentElement.closest('.snav-menu')) {
          focusParentTrigger(owningItem);
        } else {
          focusItemTrigger(owningItem);
        }
      }
    });

    document.addEventListener('click', (event) => {
      if (root.contains(event.target)) {
        return;
      }
      closeAll(root);
    });
  }

  function init() {
    document.querySelectorAll(NAV_SELECTOR).forEach((root) => initNav(root));
    openPanelFromQuery();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})();
