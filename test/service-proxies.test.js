const assert = require('node:assert/strict');
const test = require('node:test');

const {
  buildNaradaDrukRedirectUrl,
  normalizePublicHost,
  registerServiceProxies,
} = require('../middleware/serviceProxies');

function createFakeApp() {
  const handlers = [];
  return {
    handlers,
    use(handler) {
      handlers.push(handler);
    },
  };
}

function createFakeResponse() {
  return {
    statusCode: 200,
    headers: {},
    body: '',
    headersSent: false,
    status(code) {
      this.statusCode = code;
      return this;
    },
    setHeader(key, value) {
      this.headers[key.toLowerCase()] = value;
    },
    type(value) {
      this.headers['content-type'] = value;
      return this;
    },
    send(body) {
      this.body = body;
      this.headersSent = true;
    },
    redirect(code, location) {
      this.statusCode = code;
      this.headers.location = location;
      this.headersSent = true;
    },
    end() {
      this.headersSent = true;
    },
  };
}

async function runHandlers(handlers, req, res) {
  let index = 0;
  const next = () => {
    index += 1;
    const handler = handlers[index];
    if (handler) {
      return handler(req, res, next);
    }
    return undefined;
  };
  return handlers[0](req, res, next);
}

test('withlforl proxy path is claimed by service middleware', async () => {
  const app = createFakeApp();
  registerServiceProxies(app, {
    env: {},
    logger: { error() {} },
  });

  const res = createFakeResponse();
  await runHandlers(app.handlers, { path: '/withlforl', url: '/withlforl' }, res);

  assert.equal(res.statusCode, 404);
  assert.equal(res.body, 'Not found');
  assert.match(res.headers['cache-control'], /no-store/);
});

test('withlforl child paths are claimed by service middleware', async () => {
  const app = createFakeApp();
  registerServiceProxies(app, {
    env: {},
    logger: { error() {} },
  });

  const res = createFakeResponse();
  await runHandlers(app.handlers, { path: '/withlforl/api/access', url: '/withlforl/api/access' }, res);

  assert.equal(res.statusCode, 404);
  assert.equal(res.body, 'Not found');
});

test('osix proxy path is claimed by service middleware', async () => {
  const app = createFakeApp();
  registerServiceProxies(app, {
    env: {},
    logger: { error() {} },
  });

  const res = createFakeResponse();
  await runHandlers(app.handlers, { path: '/osix', url: '/osix' }, res);

  assert.equal(res.statusCode, 404);
  assert.equal(res.body, 'Not found');
});

test('osix child paths are claimed by service middleware', async () => {
  const app = createFakeApp();
  registerServiceProxies(app, {
    env: {},
    logger: { error() {} },
  });

  const res = createFakeResponse();
  await runHandlers(app.handlers, { path: '/osix/api/v1/health/live', url: '/osix/api/v1/health/live' }, res);

  assert.equal(res.statusCode, 404);
  assert.equal(res.body, 'Not found');
});

test('shieldline proxy path is claimed by service middleware', async () => {
  const app = createFakeApp();
  registerServiceProxies(app, {
    env: {},
    logger: { error() {} },
  });

  const res = createFakeResponse();
  await runHandlers(app.handlers, { path: '/shieldline', url: '/shieldline' }, res);

  assert.equal(res.statusCode, 404);
  assert.equal(res.body, 'Not found');
});

test('shieldline child paths are claimed by service middleware', async () => {
  const app = createFakeApp();
  registerServiceProxies(app, {
    env: {},
    logger: { error() {} },
  });

  const res = createFakeResponse();
  await runHandlers(app.handlers, { path: '/shieldline/day/1', url: '/shieldline/day/1' }, res);

  assert.equal(res.statusCode, 404);
  assert.equal(res.body, 'Not found');
});

test('ykg proxy path is claimed by its isolated service middleware', async () => {
  const app = createFakeApp();
  registerServiceProxies(app, { env: {}, logger: { error() {} } });
  const res = createFakeResponse();
  await runHandlers(app.handlers, { path: '/ykg', url: '/ykg' }, res);
  assert.equal(res.statusCode, 404);
  assert.equal(res.body, 'Not found');
});

test('ykg proxy does not claim a similar prefix', async () => {
  const app = createFakeApp();
  registerServiceProxies(app, { env: {}, logger: { error() {} } });
  const res = createFakeResponse();
  await runHandlers(app.handlers, { path: '/ykg-old', url: '/ykg-old' }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body, '');
});

test('naradadruk public host normalization accepts a hostname and rejects a URL', () => {
  assert.equal(normalizePublicHost(' NaradaDruk.Studerria.com '), 'naradadruk.studerria.com');
  assert.equal(normalizePublicHost('https://naradadruk.studerria.com'), '');
  assert.equal(normalizePublicHost('naradadruk.studerria.com/path'), '');
});

test('naradadruk legacy URLs map to the matching subdomain path', () => {
  assert.equal(
    buildNaradaDrukRedirectUrl(
      { originalUrl: '/naradadruk/product/test-model?variant=2' },
      'naradadruk.studerria.com',
    ),
    'https://naradadruk.studerria.com/product/test-model?variant=2',
  );
  assert.equal(
    buildNaradaDrukRedirectUrl(
      { originalUrl: '/naradadruk' },
      'naradadruk.studerria.com',
    ),
    'https://naradadruk.studerria.com/',
  );
});

test('naradadruk subdomain claims root requests only when the cutover host is configured', async () => {
  const app = createFakeApp();
  registerServiceProxies(app, {
    env: { NARADADRUK_PUBLIC_HOST: 'naradadruk.studerria.com' },
    logger: { error() {} },
  });

  const res = createFakeResponse();
  await runHandlers(app.handlers, {
    path: '/',
    url: '/',
    headers: { host: 'naradadruk.studerria.com' },
  }, res);

  assert.equal(res.statusCode, 404);
  assert.equal(res.body, 'Not found');
});

test('naradadruk old paths redirect after the public host switch is enabled', async () => {
  const app = createFakeApp();
  registerServiceProxies(app, {
    env: { NARADADRUK_PUBLIC_HOST: 'naradadruk.studerria.com' },
    logger: { error() {} },
  });

  const res = createFakeResponse();
  await runHandlers(app.handlers, {
    path: '/naradadruk/catalog',
    url: '/naradadruk/catalog?q=mount',
    originalUrl: '/naradadruk/catalog?q=mount',
    headers: { host: 'studerria.com' },
  }, res);

  assert.equal(res.statusCode, 308);
  assert.equal(
    res.headers.location,
    'https://naradadruk.studerria.com/catalog?q=mount',
  );
});

test('obriy claims its isolated path but not similar names', async () => {
  const app = createFakeApp();
  registerServiceProxies(app, { env: {}, logger: { error() {} } });
  for (const pathname of ['/obriy', '/obriy/api/v1/zones']) {
    const res = createFakeResponse();
    await runHandlers(app.handlers, { path: pathname, url: pathname }, res);
    assert.equal(res.statusCode, 404);
    assert.equal(res.body, 'Not found');
  }
  const res = createFakeResponse();
  await runHandlers(app.handlers, { path: '/obriy-other', url: '/obriy-other' }, res);
  assert.equal(res.headersSent, false);
});
