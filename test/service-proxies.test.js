const assert = require('node:assert/strict');
const test = require('node:test');

const { registerServiceProxies } = require('../middleware/serviceProxies');

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
