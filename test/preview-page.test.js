const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const ejs = require('ejs');
const { registerPublicRoutes } = require('../routes/publicRoutes');

const viewsDir = path.join(__dirname, '..', 'views');

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
  assert.match(html, /src="\/assets\/brand\/studerria-mark-512\.png"/);
  assert.doesNotMatch(html, /td-login-card|app-footer|studerria-navbar/);
});
