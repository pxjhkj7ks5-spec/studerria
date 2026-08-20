(() => {
  const root = document.documentElement;
  const hero = document.querySelector('.landing-hero');
  const header = document.querySelector('[data-landing-header]');
  const menuToggle = document.querySelector('[data-menu-toggle]');
  const navigation = document.querySelector('[data-navigation]');
  const revealItems = Array.from(document.querySelectorAll('[data-reveal]'));
  const changelog = document.querySelector('[data-auth-changelog]');
  const changelogOpen = document.querySelector('[data-auth-changelog-open]');
  const changelogClose = Array.from(document.querySelectorAll('[data-auth-changelog-close]'));
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  let scrollFrame = 0;
  let previousFocus = null;

  const setMenu = (isOpen) => {
    if (!menuToggle || !navigation) return;
    menuToggle.setAttribute('aria-expanded', String(isOpen));
    menuToggle.setAttribute(
      'aria-label',
      isOpen ? menuToggle.dataset.closeLabel : menuToggle.dataset.openLabel,
    );
    header?.classList.toggle('is-menu-open', isOpen);
    navigation.classList.toggle('is-open', isOpen);
    document.body.classList.toggle('landing-menu-open', isOpen);
  };

  const updateScrollState = () => {
    scrollFrame = 0;
    const scrollTop = window.scrollY;
    header?.classList.toggle('is-scrolled', scrollTop > 24);
    if (!reduceMotion.matches) {
      root.style.setProperty('--hero-shift', `${Math.min(scrollTop * 0.11, 72)}px`);
    }
  };

  const requestScrollUpdate = () => {
    if (!scrollFrame) scrollFrame = window.requestAnimationFrame(updateScrollState);
  };

  const setChangelog = (isOpen) => {
    if (!changelog) return;
    if (isOpen) {
      previousFocus = document.activeElement;
      changelog.hidden = false;
      document.body.classList.add('landing-modal-open');
      window.requestAnimationFrame(() => {
        changelog.classList.add('is-open');
        changelog.querySelector('.td-lite-sheet')?.focus();
      });
      return;
    }

    changelog.classList.remove('is-open');
    changelog.hidden = true;
    document.body.classList.remove('landing-modal-open');
    if (previousFocus instanceof HTMLElement) previousFocus.focus();
  };

  hero?.classList.add('is-ready');
  updateScrollState();

  if ('IntersectionObserver' in window && !reduceMotion.matches) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        });
      },
      { rootMargin: '0px 0px -12% 0px', threshold: 0.08 },
    );
    revealItems.forEach((item) => observer.observe(item));
  } else {
    revealItems.forEach((item) => item.classList.add('is-visible'));
  }

  menuToggle?.addEventListener('click', () => {
    setMenu(menuToggle.getAttribute('aria-expanded') !== 'true');
  });

  navigation?.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', () => setMenu(false));
  });

  changelogOpen?.addEventListener('click', () => setChangelog(true));
  changelogClose.forEach((button) => button.addEventListener('click', () => setChangelog(false)));

  window.addEventListener('scroll', requestScrollUpdate, { passive: true });
  reduceMotion.addEventListener('change', () => {
    if (reduceMotion.matches) root.style.removeProperty('--hero-shift');
    revealItems.forEach((item) => item.classList.add('is-visible'));
    requestScrollUpdate();
  });

  document.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape') return;
    if (changelog && !changelog.hidden) setChangelog(false);
    setMenu(false);
  });
})();
