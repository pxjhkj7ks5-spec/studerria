function registerPublicRoutes(app, deps) {
  const {
    getPreferredLang,
    buildLoginErrorMessage,
    publicLegalPages,
  } = deps;

  app.get('/', (req, res) => {
    if (req.session && req.session.user) {
      return res.redirect('/home');
    }
    const lang = getPreferredLang(req);
    const loginErrorText = buildLoginErrorMessage(lang, req.query.error);
    res.render('login', {
      error: Boolean(loginErrorText),
      loginErrorText,
      layout: false,
    });
  });

  app.get('/login', (req, res) => {
    if (req.session && req.session.user) {
      return res.redirect('/home');
    }
    const lang = getPreferredLang(req);
    const loginErrorText = buildLoginErrorMessage(lang, req.query.error);
    res.render('login', {
      error: Boolean(loginErrorText),
      loginErrorText,
      layout: false,
    });
  });

  app.get(['/terms', '/privacy'], (req, res) => {
    const lang = getPreferredLang(req);
    const legalLang = lang === 'en' ? 'en' : 'uk';
    const key = req.path === '/privacy' ? 'privacy' : 'terms';
    return res.render('legal', {
      ...publicLegalPages[legalLang][key],
      layout: false,
    });
  });

  app.get('/changelog', (req, res) => res.render('changelog', { layout: false }));
}

module.exports = {
  registerPublicRoutes,
};
