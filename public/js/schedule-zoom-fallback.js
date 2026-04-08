(() => {
  const ROOT_CLASS = 'studerria-zoom-fallback';
  const DESKTOP_MIN_WIDTH = 1200;
  let nativeZoomWorks;

  function detectZoomSupport() {
    if (nativeZoomWorks !== undefined) {
      return nativeZoomWorks;
    }

    const host = document.body || document.documentElement;
    if (!(host instanceof HTMLElement)) {
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
    host.appendChild(probe);
    nativeZoomWorks = Math.round(probe.getBoundingClientRect().width) === 240;
    probe.remove();
    return nativeZoomWorks;
  }

  function syncScheduleZoomFallback() {
    const body = document.body;
    const root = document.documentElement;
    if (!(body instanceof HTMLElement) || !(root instanceof HTMLElement)) {
      return;
    }

    const shouldUseFallback =
      body.classList.contains('studerria-theme') &&
      body.classList.contains('page-schedule') &&
      window.innerWidth >= DESKTOP_MIN_WIDTH &&
      !detectZoomSupport();

    root.classList.toggle(ROOT_CLASS, shouldUseFallback);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', syncScheduleZoomFallback, { once: true });
  } else {
    syncScheduleZoomFallback();
  }

  window.addEventListener('resize', syncScheduleZoomFallback, { passive: true });
})();
