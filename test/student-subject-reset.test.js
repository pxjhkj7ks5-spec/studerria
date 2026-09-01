const test = require('node:test');
const assert = require('node:assert/strict');
const { getStudentSubjectChoiceSummary, resetAllStudentSubjectChoices } = require('../lib/studentSubjectReset');

function fixture(failAt = '') {
  let state = {
    selections: [
      { id: 1, student_id: 10, subject_id: 21, group_number: 1 },
      { id: 2, student_id: 10, subject_id: 22, group_number: 2 },
      { id: 3, student_id: 11, subject_id: 31, group_number: 1 },
    ],
    optouts: [
      { id: 4, user_id: 10, subject_id: 23, created_at: '2026-09-01T10:00:00Z' },
      { id: 5, user_id: 12, subject_id: 32, created_at: '2026-09-01T10:00:00Z' },
    ],
    history: [],
    unrelated: { grades: [90], schedule: [2], users: [10, 11, 12], enrollments: [1], teacherAssignments: [2], teamwork: [3] },
  };
  const before = structuredClone(state);
  const queries = [];
  const store = {
    withTransaction: async (work) => {
      const draft = structuredClone(state);
      const tx = {
        all: async (sql) => {
          queries.push(sql);
          if (sql.includes('FROM student_groups')) return structuredClone(draft.selections);
          if (sql.includes('FROM user_subject_optouts')) return structuredClone(draft.optouts);
          throw new Error(`Unexpected all: ${sql}`);
        },
        get: async (sql, params) => {
          queries.push(sql);
          if (sql.startsWith('SELECT id, full_name FROM users')) {
            assert.deepEqual(params, ['123']);
            return { id: 7, full_name: 'Test dev' };
          }
          if (sql.includes('INSERT INTO history_log')) {
            if (failAt === 'audit') throw new Error('audit failed');
            draft.history.push({ id: 99, actorId: params[0], actorName: params[1], action: params[2], details: JSON.parse(params[3]) });
            return { id: 99 };
          }
          throw new Error(`Unexpected get: ${sql}`);
        },
        run: async (sql, params) => {
          queries.push(sql);
          if (sql.startsWith('SET LOCAL') || sql.startsWith('LOCK TABLE')) return;
          assert.equal(draft.history.length, 1, 'backup must be written before deletion');
          if (sql === 'DELETE FROM student_groups WHERE id = ANY(?::int[])') {
            draft.selections = draft.selections.filter((row) => !params[0].includes(row.id));
            return;
          }
          if (sql === 'DELETE FROM user_subject_optouts WHERE id = ANY(?::int[])') {
            if (failAt === 'optouts') throw new Error('second delete failed');
            draft.optouts = draft.optouts.filter((row) => !params[0].includes(row.id));
            return;
          }
          throw new Error(`Unexpected mutation: ${sql}`);
        },
      };
      const result = await work(tx);
      state = draft;
      return result;
    },
  };
  return { store, before, queries, state: () => state };
}

test('summary counts distinct users including optout-only users', async () => {
  const summary = await getStudentSubjectChoiceSummary({ get: async (sql) => {
    assert.match(sql, /SELECT student_id AS user_id FROM student_groups\s+UNION\s+SELECT user_id FROM user_subject_optouts/);
    return { users: '3', selections: '3', optouts: '2' };
  } });
  assert.deepEqual(summary, { users: 3, selections: 3, optouts: 2 });
});

test('reset atomically backs up both selection stores, clears all users, and preserves other data', async () => {
  const f = fixture();
  const result = await resetAllStudentSubjectChoices(f.store, { actorTelegramId: 123 });
  assert.deepEqual(result, { users: 3, selections: 3, optouts: 2, auditId: 99 });
  assert.deepEqual(f.state().selections, []);
  assert.deepEqual(f.state().optouts, []);
  assert.deepEqual(f.state().unrelated, f.before.unrelated);
  const audit = f.state().history[0];
  assert.equal(audit.actorId, 7);
  assert.equal(audit.action, 'telegram_dev_reset_subjects_all');
  assert.equal(audit.details.actor_telegram_id, '123');
  assert.deepEqual(audit.details.backup, { student_groups: f.before.selections, user_subject_optouts: f.before.optouts });
  assert.match(f.queries[0], /lock_timeout/);
  assert.match(f.queries[1], /statement_timeout/);
  assert.match(f.queries[2], /LOCK TABLE student_groups, user_subject_optouts IN SHARE ROW EXCLUSIVE MODE/);
});

test('failed backup or second deletion rolls back selection changes and audit together', async () => {
  for (const failAt of ['audit', 'optouts']) {
    const f = fixture(failAt);
    await assert.rejects(resetAllStudentSubjectChoices(f.store, { actorTelegramId: '123' }), /failed/);
    assert.deepEqual(f.state(), f.before);
  }
});

test('destructive operation fails closed without a transaction or valid actor ID', async () => {
  for (const actorTelegramId of [undefined, '', 0, -123, 'dev']) {
    await assert.rejects(resetAllStudentSubjectChoices({}, { actorTelegramId }), /RESET_ACTOR_REQUIRED/);
  }
  await assert.rejects(resetAllStudentSubjectChoices({}, { actorTelegramId: 123 }), /RESET_TRANSACTION_REQUIRED/);
});
