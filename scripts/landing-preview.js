const path = require('node:path');
const fs = require('node:fs');
const express = require('express');
const { registerPublicRoutes } = require('../routes/publicRoutes');

const projectRoot = path.resolve(__dirname, '..');
const app = express();
const port = Number.parseInt(process.env.LANDING_PREVIEW_PORT || '3000', 10);
const version = JSON.parse(fs.readFileSync(path.join(projectRoot, 'version.json'), 'utf8'));
const changelog = JSON.parse(fs.readFileSync(path.join(projectRoot, 'changelog.json'), 'utf8'));
const locales = {
  uk: JSON.parse(fs.readFileSync(path.join(projectRoot, 'locales/uk.json'), 'utf8')),
  en: JSON.parse(fs.readFileSync(path.join(projectRoot, 'locales/en.json'), 'utf8')),
};

app.set('view engine', 'ejs');
app.set('views', path.join(projectRoot, 'views'));
app.use(express.static(path.join(projectRoot, 'public')));
app.use('/naradadruk', express.static(path.join(projectRoot, 'services/naradadruk/public')));
app.use('/shieldline', express.static(path.join(projectRoot, 'services/shieldline/public')));

app.use((req, res, next) => {
  const lang = req.query.lang === 'en' ? 'en' : 'uk';
  res.locals.appVersion = version.version;
  res.locals.changelog = Array.isArray(changelog.items) ? changelog.items : [];
  res.locals.lang = lang;
  res.locals.t = (key) => locales[lang][key] || key;
  next();
});

registerPublicRoutes(app, {
  getPreferredLang: (req) => (req.query.lang === 'en' ? 'en' : 'uk'),
  buildLoginErrorMessage: () => '',
  publicLegalPages: {
    uk: { privacy: {}, terms: {} },
    en: { privacy: {}, terms: {} },
  },
});

app.listen(port, '127.0.0.1', () => {
  console.log(`Landing preview: http://localhost:${port}/`);
});
