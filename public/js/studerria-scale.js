(() => {
  const ROOT_CLASS = 'studerria-scale-fallback';
  const DESKTOP_MIN_WIDTH = 1200;
  let nativeZoomWorks;

  function detectZoomSupport() {
    if (nativeZoomWorks !== undefined) {
      return nativeZoomWorks;
    }
    if (!(document.body instanceof HTMLElement)) {
      nativeZoomWorks = true;
      return nativeZoomWorks;
    }

    const probe = document.createElement('div');
    probe.style.position = 'absolute';
    probe.style.left = '-9999px';
    probe.style.top = '-9999px';
    probe.style.width = '120px';
    probe.style.height = '8px';
    probe.style.visibility = 'hidden';
    probe.style.pointerEvents = 'none';
    probe.style.zoom = '2';
    document.body.appendChild(probe);
    nativeZoomWorks = Math.round(probe.getBoundingClientRect().width) === 240;
    probe.remove();
    return nativeZoomWorks;
  }

  function syncStuderriaScaleFallback() {
    const body = document.body;
    const root = document.documentElement;
    if (!(body instanceof HTMLElement) || !(root instanceof HTMLElement)) {
      return;
    }

    if (!body.classList.contains('studerria-theme')) {
      root.classList.remove(ROOT_CLASS);
      return;
    }

    const shouldUseFallback = window.innerWidth >= DESKTOP_MIN_WIDTH && !detectZoomSupport();
    root.classList.toggle(ROOT_CLASS, shouldUseFallback);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', syncStuderriaScaleFallback, { once: true });
  } else {
    syncStuderriaScaleFallback();
  }

  window.addEventListener('resize', syncStuderriaScaleFallback, { passive: true });
})();
