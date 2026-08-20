const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const ejs = require('ejs');
const {
  LANDING_COPY,
  LANDING_PRODUCTS,
  registerPublicRoutes,
} = require('../routes/publicRoutes');

const projectRoot = path.resolve(__dirname, '..');
const viewPath = path.join(projectRoot, 'views/landing.ejs');

function captureRootRoute(lang = 'uk') {
  let handler;
  const app = {
    get(route, candidate) {
      if (route === '/') handler = candidate;
    },
  };

  registerPublicRoutes(app, {
    getPreferredLang: () => lang,
    buildLoginErrorMessage: () => '',
    publicLegalPages: { uk: { privacy: {}, terms: {} }, en: { privacy: {}, terms: {} } },
  });
  return handler;
}

async function renderLanding(lang) {
  const handler = captureRootRoute(lang);
  let rendered;
  handler(
    { session: null },
    {
      render(view, locals) {
        rendered = { view, locals };
      },
    },
  );

  const dictionary = JSON.parse(
    fs.readFileSync(path.join(projectRoot, `locales/${lang}.json`), 'utf8'),
  );
  const html = await ejs.renderFile(viewPath, {
    ...rendered.locals,
    appVersion: '1.12.69',
    changelog: [],
    t: (key) => dictionary[key] || key,
  });
  return { ...rendered, html };
}

test('GET / renders the public landing with HTTP content instead of redirecting', () => {
  const handler = captureRootRoute('uk');
  let rendered;
  const res = {
    redirect() {
      assert.fail('root route must not redirect');
    },
    render(view, locals) {
      rendered = { view, locals };
    },
  };

  handler({ session: null }, res);
  assert.equal(rendered.view, 'landing');
  assert.equal(rendered.locals.layout, false);
  assert.equal(rendered.locals.platformUrl, '/login');
  assert.equal(rendered.locals.structuredData['@graph'][0]['@type'], 'WebSite');
  assert.equal(rendered.locals.structuredData['@graph'][1]['@type'], 'ItemList');
});

test('authenticated visitors keep a direct platform action', () => {
  const handler = captureRootRoute('en');
  let locals;
  handler(
    { session: { user: { id: 1 } } },
    { render(_view, payload) { locals = payload; } },
  );
  assert.equal(locals.platformUrl, '/home');
  assert.equal(locals.landingLang, 'en');
});

test('landing renders full Ukrainian and English versions', async () => {
  const uk = await renderLanding('uk');
  const en = await renderLanding('en');

  assert.match(uk.html, /Одна команда\./);
  assert.match(uk.html, /Різні продукти\./);
  assert.match(en.html, /One team\./);
  assert.match(en.html, /Different products\./);
  assert.match(en.html, /<html lang="en"/);
  assert.match(uk.html, /hreflang="uk"/);
  assert.match(en.html, /application\/ld\+json/);
});

test('landing includes every approved public destination and keeps YKG inactive', async () => {
  const { html } = await renderLanding('uk');
  const approvedUrls = [
    '/naradadruk',
    'https://t.me/naradaprint',
    '/login',
    'https://t.me/studerria_bot',
    '/charredmap',
    '/shieldline',
    'https://t.me/ShieldLinebot',
  ];

  approvedUrls.forEach((url) => assert.match(html, new RegExp(`href="${url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"`)));
  assert.doesNotMatch(html, /href="\/ykg(?:[/?#]|\")/i);
  assert.match(html, /Незабаром/);
  assert.deepEqual(LANDING_PRODUCTS.map((product) => product.id), [
    'naradadruk', 'studerria', 'telegram', 'charredmap', 'shieldline', 'ykg',
  ]);
});

test('landing excludes private projects, personal data, and unapproved claims', async () => {
  const { html } = await renderLanding('en');
  const excluded = [
    'WithLforL',
    'China Map',
    'OSIX',
    'Slash TG',
    '/withlforl',
    '/china-map',
    '/osix',
    'Andrii Marchenko',
    'Андрій Марченко',
  ];
  excluded.forEach((value) => assert.doesNotMatch(html, new RegExp(value, 'i')));
  assert.doesNotMatch(html, /contact form|контактна форма/i);
});

test('landing assets include accessible focus and reduced-motion fallbacks', () => {
  const css = fs.readFileSync(path.join(projectRoot, 'public/css/pages/landing.css'), 'utf8');
  const js = fs.readFileSync(path.join(projectRoot, 'public/js/landing.js'), 'utf8');
  assert.match(css, /:focus-visible/);
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
  assert.match(js, /prefers-reduced-motion:\s*reduce/);
  assert.match(js, /IntersectionObserver/);
});

test('landing copy exists for every declared product in both languages', () => {
  for (const lang of ['uk', 'en']) {
    for (const product of LANDING_PRODUCTS) {
      assert.ok(LANDING_COPY[lang].products[product.id]);
    }
  }
});
