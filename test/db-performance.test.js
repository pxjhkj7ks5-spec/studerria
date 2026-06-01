const assert = require('node:assert/strict');
const test = require('node:test');

const {
  buildMaintenanceStatements,
  buildQueryLogPayload,
  buildRetentionDeleteSql,
  normalizeSqlForLog,
  parseSlowQueryThreshold,
  quoteIdentifier,
} = require('../lib/dbPerformance');

test('normalizeSqlForLog compacts whitespace and caps long statements', () => {
  const sql = `SELECT *
    FROM users
    WHERE id = ?`;
  assert.equal(normalizeSqlForLog(sql), 'SELECT * FROM users WHERE id = ?');
  assert.equal(normalizeSqlForLog('x'.repeat(600)).length, 500);
});

test('parseSlowQueryThreshold supports disabling slow query logs', () => {
  assert.equal(parseSlowQueryThreshold('1200'), 1200);
  assert.equal(parseSlowQueryThreshold('-1'), 0);
  assert.equal(parseSlowQueryThreshold('bad', 900), 900);
});

test('maintenance statements quote known identifiers', () => {
  assert.deepEqual(buildMaintenanceStatements(['users'], { mode: 'analyze' }), ['ANALYZE "users"']);
  assert.deepEqual(buildMaintenanceStatements(['users'], { mode: 'vacuum' }), ['VACUUM (ANALYZE) "users"']);
  assert.throws(() => quoteIdentifier('users;DROP'), /Invalid identifier/);
});

test('retention delete SQL keeps frozen records when target supports holds', () => {
  const plan = buildRetentionDeleteSql({
    table: 'site_visit_events',
    dateColumn: 'created_at',
    defaultDays: 90,
    supportsFreeze: true,
  });
  assert.equal(plan.days, 90);
  assert.match(plan.sql, /DELETE FROM "site_visit_events"/);
  assert.match(plan.sql, /COALESCE\(is_frozen, false\) = false/);
});

test('query log payload does not include parameter values', () => {
  const payload = buildQueryLogPayload({
    sql: 'SELECT * FROM users WHERE password_hash = ?',
    params: ['secret'],
    durationMs: 901,
  });
  assert.equal(payload.params_count, 1);
  assert.equal(Object.values(payload).includes('secret'), false);
});
