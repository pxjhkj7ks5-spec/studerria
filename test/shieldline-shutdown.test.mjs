import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { installShutdown } from '../services/shieldline/serverShutdown.mjs';

test('shutdown drains an active request before telemetry and successful exit', async () => {
  let release;
  const server = createServer((req, res) => { release = () => res.end('ok'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const request = fetch(`http://127.0.0.1:${server.address().port}`);
  while (!release) await new Promise(resolve => setTimeout(resolve, 5));
  let telemetry = false;
  let finish;
  const done = new Promise(resolve => { finish = resolve; });
  const remove = installShutdown(server, async () => { telemetry = true; }, { exit: finish });
  try {
    process.emit('SIGTERM');
    process.emit('SIGTERM');
    assert.equal(telemetry, false);
    release();
    assert.equal(await (await request).text(), 'ok');
    assert.equal(await done, 0);
    assert.equal(telemetry, true);
  } finally { remove(); server.closeAllConnections(); }
});

test('telemetry failure is not reported as graceful success', async () => {
  let finish;
  const done = new Promise(resolve => { finish = resolve; });
  const remove = installShutdown({ close: cb => cb(), closeIdleConnections() {} },
    async () => { throw new Error('failure'); }, { exit: finish });
  try { process.emit('SIGINT'); assert.equal(await done, 1); } finally { remove(); }
});
