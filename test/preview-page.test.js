const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ejs = require('ejs');
const { registerPublicRoutes } = require('../routes/publicRoutes');

const viewsDir = path.join(__dirname, '..', 'views');
const brandDir = path.join(__dirname, '..', 'public', 'assets', 'brand');

test('preview route renders the standalone preview page without auth', () => {
  const routes = new Map();
  const app = {
    get(routePath, handler) {
      if (routePath === '/preview') {
        routes.set(routePath, handler);
      }
    },
  };

  registerPublicRoutes(app, {
    getPreferredLang: () => 'uk',
    buildLoginErrorMessage: () => '',
    publicLegalPages: {
      uk: { terms: {}, privacy: {} },
      en: { terms: {}, privacy: {} },
    },
  });

  const handler = routes.get('/preview');
  assert.equal(typeof handler, 'function');

  const res = {
    rendered: null,
    render(view, locals) {
      this.rendered = { view, locals };
    },
  };

  handler({ session: {} }, res);

  assert.deepEqual(res.rendered, {
    view: 'preview',
    locals: { layout: false },
  });
});

test('preview page renders only the brand mark shell', async () => {
  const html = await ejs.renderFile(path.join(viewsDir, 'preview.ejs'), {}, {
    filename: path.join(viewsDir, 'preview.ejs'),
  });

  assert.match(html, /class="preview-page"/);
  assert.match(html, /src="\/assets\/brand\/mzs-logo\.svg"/);
  assert.doesNotMatch(html, /td-login-card|app-footer|studerria-navbar/);
});

test('mzs logo svg embeds the measured reference crop', () => {
  const svg = fs.readFileSync(path.join(brandDir, 'mzs-logo.svg'), 'utf8');

  assert.match(svg, /width="508" height="572" viewBox="247 225 508 572"/);
  assert.match(svg, /href="data:image\/jpeg;base64,/);
  assert.doesNotMatch(svg, /font-family|<text\b/);
});
