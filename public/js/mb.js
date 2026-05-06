(() => {
  const page = document.querySelector('[data-gift-page]');
  const button = document.querySelector('[data-gift-open]');

  if (!page || !button) return;

  const openGift = () => {
    page.classList.add('is-open');
    button.setAttribute('aria-expanded', 'true');
    button.disabled = true;
  };

  button.addEventListener('click', openGift, { once: true });
})();
