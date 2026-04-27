(() => {
  const root = document.getElementById('dynamic-bg');
  const body = document.body;
  if (!root || !body) {
    return;
  }

  const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const coarsePointerQuery = window.matchMedia('(pointer: coarse)');

  function applyMode() {
    body.classList.add('dynamic-bg-ready');
    body.classList.toggle('dynamic-bg-reduced', reducedMotionQuery.matches);
    body.classList.toggle('dynamic-bg-coarse', coarsePointerQuery.matches);
  }

  applyMode();

  if (typeof reducedMotionQuery.addEventListener === 'function') {
    reducedMotionQuery.addEventListener('change', applyMode);
    coarsePointerQuery.addEventListener('change', applyMode);
  } else if (typeof reducedMotionQuery.addListener === 'function') {
    reducedMotionQuery.addListener(applyMode);
    coarsePointerQuery.addListener(applyMode);
  }

  if (!window.__studerriaBackgroundInitialized && !document.querySelector('script[data-studerria-background-runtime]')) {
    const script = document.createElement('script');
    script.src = '/js/studerria-background.js';
    script.defer = true;
    script.setAttribute('data-studerria-background-runtime', 'true');
    document.head.appendChild(script);
  }
})();
