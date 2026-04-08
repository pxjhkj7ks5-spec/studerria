(function initCsrfProtection() {
  'use strict';

  function getToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') || '' : '';
  }

  /* Auto-inject hidden _csrf field into every <form method="POST"> */
  function injectIntoForms() {
    var token = getToken();
    if (!token) return;
    var forms = document.querySelectorAll('form');
    for (var i = 0; i < forms.length; i++) {
      var form = forms[i];
      var method = (form.getAttribute('method') || 'GET').toUpperCase();
      if (method === 'GET' || method === 'HEAD') continue;
      if (form.querySelector('input[name="_csrf"]')) continue;
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = '_csrf';
      input.value = token;
      form.appendChild(input);
    }
  }

  /* Observe DOM for dynamically added forms */
  function observeForms() {
    if (typeof MutationObserver === 'undefined') return;
    new MutationObserver(function () { injectIntoForms(); })
      .observe(document.body, { childList: true, subtree: true });
  }

  /* Patch fetch to include CSRF header on same-origin requests */
  var originalFetch = window.fetch;
  if (typeof originalFetch === 'function') {
    window.fetch = function csrfFetch(input, init) {
      init = init || {};
      var method = (init.method || 'GET').toUpperCase();
      if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
        var url = typeof input === 'string' ? input : (input && input.url ? input.url : '');
        var isSameOrigin = !url || url.startsWith('/') || url.startsWith(location.origin);
        if (isSameOrigin) {
          init.headers = init.headers || {};
          if (init.headers instanceof Headers) {
            if (!init.headers.has('X-CSRF-Token')) {
              init.headers.set('X-CSRF-Token', getToken());
            }
          } else {
            if (!init.headers['X-CSRF-Token']) {
              init.headers['X-CSRF-Token'] = getToken();
            }
          }
        }
      }
      return originalFetch.call(this, input, init);
    };
  }

  /* Patch XMLHttpRequest to include CSRF header */
  var origOpen = XMLHttpRequest.prototype.open;
  var origSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method) {
    this._csrfMethod = (method || 'GET').toUpperCase();
    return origOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    if (this._csrfMethod && this._csrfMethod !== 'GET' && this._csrfMethod !== 'HEAD') {
      try { this.setRequestHeader('X-CSRF-Token', getToken()); } catch (_e) { /* noop */ }
    }
    return origSend.apply(this, arguments);
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      injectIntoForms();
      observeForms();
    });
  } else {
    injectIntoForms();
    observeForms();
  }
})();
