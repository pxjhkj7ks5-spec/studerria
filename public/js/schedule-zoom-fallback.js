(() => {
  const ROOT_CLASS = 'studerria-zoom-fallback';
  const APPLE_WEBVIEW_CLASS = 'studerria-apple-webview';
  const DESKTOP_MIN_WIDTH = 1200;
  let nativeZoomWorks;

  /* Mirror the same heuristic used by changelog-modal.js so we can prime the
     Atlas body class before changelog-modal.js fires (both scripts are deferred
     but schedule-zoom-fallback appears earlier in the document). */
  function detectAtlasAppleWebView() {
    const ua = String(navigator.userAgent || '');
    const vendor = String(navigator.vendor || '');
    const platform = String(navigator.platform || '');
    const isApple =
      /(Mac|iPhone|iPad|iPod)/i.test(platform) || /(Macintosh|iPhone|iPad|iPod)/i.test(ua);
    const isWebKit = /AppleWebKit/i.test(ua) || /Apple/i.test(vendor);
    const isExcluded =
      /(Chrome|Chromium|CriOS|Edg|EdgiOS|OPR|OPT|SamsungBrowser|DuckDuckGo|Firefox|FxiOS)/i.test(
        ua
      );
    const isAtlasToken = /(Atlas|ChatGPT)/i.test(ua);
    const hasSafariGlobal = typeof window.safari !== 'undefined';
    return Boolean(isAtlasToken || (isApple && isWebKit && !isExcluded && !hasSafariGlobal));
  }

  const isAtlas = detectAtlasAppleWebView();

  /* Set studerria-apple-webview on <body> as early as possible so the CSS rule
       body.studerria-theme.studerria-apple-webview { zoom: 1 }
     takes effect before layout is established, preventing the fixed-overlay
     coverage problem caused by body zoom: 0.75 in Atlas. */
  function primeAtlasBodyClass() {
    const body = document.body;
    if (body instanceof HTMLElement && isAtlas) {
      body.classList.add(APPLE_WEBVIEW_CLASS);
    }
  }

  if (document.body instanceof HTMLElement) {
    primeAtlasBodyClass();
  } else {
    document.addEventListener('DOMContentLoaded', primeAtlasBodyClass, { once: true });
  }

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

    /* Re-prime Atlas class on every sync in case DOMContentLoaded hadn't fired
       during the initial primeAtlasBodyClass call. */
    if (isAtlas) {
      body.classList.add(APPLE_WEBVIEW_CLASS);
    }

    /* Force the zoom-fallback path for Atlas on the schedule page.
       Without body zoom: 0.75, the page renders at full scale, so we need the
       component-level fallback CSS (font-size / layout vars) to keep the same
       visual density as in Safari/Chrome. */
    const shouldUseFallback =
      body.classList.contains('studerria-theme') &&
      body.classList.contains('page-schedule') &&
      window.innerWidth >= DESKTOP_MIN_WIDTH &&
      (!detectZoomSupport() || isAtlas);

    root.classList.toggle(ROOT_CLASS, shouldUseFallback);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', syncScheduleZoomFallback, { once: true });
  } else {
    syncScheduleZoomFallback();
  }

  window.addEventListener('resize', syncScheduleZoomFallback, { passive: true });
})();
