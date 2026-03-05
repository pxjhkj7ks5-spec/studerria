(() => {
  const islands = window.KMAReactIslands;
  if (!islands || typeof islands.register !== 'function') {
    return;
  }

  islands.register('footer-release-pill', ({ React, props }) => {
    if (!React || typeof React.createElement !== 'function') {
      return null;
    }

    const latestVersion = String(props && props.latestVersion ? props.latestVersion : '').trim();
    const appVersion = String(props && props.appVersion ? props.appVersion : '').trim();
    const displayVersion = latestVersion || appVersion;
    if (!displayVersion) {
      return null;
    }

    const latestDate = String(props && props.latestDate ? props.latestDate : '').trim();
    const latestLabel = latestDate ? `Updated ${latestDate}` : 'Recent release';

    return React.createElement(
      'span',
      {
        className: 'footer-release-pill',
        title: latestLabel,
      },
      React.createElement('span', { className: 'footer-release-pill__dot', 'aria-hidden': 'true' }),
      React.createElement('span', { className: 'footer-release-pill__text' }, `v${displayVersion}`)
    );
  });
})();
