const test = require('node:test');
const assert = require('node:assert/strict');

const academicV2Helpers = require('../lib/academicV2');

function compactSql(sql) {
  return String(sql || '').replace(/\s+/g, ' ').trim();
}

function normalizeTerm(row = {}) {
  return {
    id: Number(row.id || 0),
    group_id: Number(row.group_id || 0),
    term_number: Number(row.term_number || 1),
    title: String(row.title || ''),
    start_date: row.start_date || null,
    weeks_count: Number(row.weeks_count || 15) || 15,
    is_active: row.is_active === true || Number(row.is_active) === 1,
    is_archived: row.is_archived === true || Number(row.is_archived) === 1,
  };
}

function createTermStore(initialTerms = []) {
  const state = {
    terms: initialTerms.map((row) => normalizeTerm(row)),
  };

  const tx = {
    get: async (sql, params = []) => {
      const query = compactSql(sql);

      if (
        query.includes('SELECT id, group_id, term_number, title, start_date, weeks_count, is_active, is_archived')
        && query.includes('FROM academic_v2_terms')
        && query.includes('WHERE id = ?')
        && query.includes('LIMIT 1')
      ) {
        return state.terms.find((row) => Number(row.id || 0) === Number(params[0] || 0)) || null;
      }

      if (
        query.includes('FROM academic_v2_terms')
        && query.includes('WHERE group_id = ?')
        && query.includes('AND term_number = ?')
        && query.includes('AND (? = 0 OR id <> ?)')
      ) {
        return state.terms.find((row) => (
          Number(row.group_id || 0) === Number(params[0] || 0)
          && Number(row.term_number || 0) === Number(params[1] || 0)
          && (Number(params[2] || 0) === 0 || Number(row.id || 0) !== Number(params[3] || 0))
        )) || null;
      }

      if (
        query.includes('UPDATE academic_v2_terms')
        && query.includes('SET')
        && query.includes('WHERE id = ?')
        && query.includes('RETURNING *')
      ) {
        const row = state.terms.find((item) => Number(item.id || 0) === Number(params[7] || 0));
        if (!row) {
          return null;
        }
        row.group_id = Number(params[0] || 0);
        row.term_number = Number(params[1] || 1);
        row.title = String(params[2] || '');
        row.start_date = params[3] || null;
        row.weeks_count = Number(params[4] || 15) || 15;
        row.is_active = params[5] === true || Number(params[5]) === 1;
        row.is_archived = params[6] === true || Number(params[6]) === 1;
        return { ...row };
      }

      throw new Error(`Unexpected get query: ${query}`);
    },
    all: async (sql, params = []) => {
      const query = compactSql(sql);
      if (
        query.includes('SELECT id, group_id, term_number, title, start_date, weeks_count, is_active, is_archived')
        && query.includes('FROM academic_v2_terms')
        && query.includes('WHERE group_id = ?')
        && query.includes('ORDER BY term_number ASC, id ASC')
      ) {
        return state.terms
          .filter((row) => Number(row.group_id || 0) === Number(params[0] || 0))
          .slice()
          .sort((left, right) => (
            Number(left.term_number || 0) - Number(right.term_number || 0)
            || Number(left.id || 0) - Number(right.id || 0)
          ))
          .map((row) => ({ ...row }));
      }
      throw new Error(`Unexpected all query: ${query}`);
    },
    run: async (sql, params = []) => {
      const query = compactSql(sql);

      if (
        query.includes('UPDATE academic_v2_terms')
        && query.includes('SET is_active = CASE WHEN id = ? THEN TRUE ELSE FALSE END')
        && query.includes('WHERE group_id = ?')
      ) {
        state.terms.forEach((row) => {
          if (Number(row.group_id || 0) !== Number(params[1] || 0)) {
            return;
          }
          row.is_active = Number(row.id || 0) === Number(params[0] || 0);
        });
        return;
      }

      throw new Error(`Unexpected run query: ${query}`);
    },
  };

  return {
    state,
    withTransaction: async (work) => work(tx),
  };
}

async function withMutedProjectionErrors(work) {
  const originalConsoleError = console.error;
  console.error = () => {};
  try {
    return await work();
  } finally {
    console.error = originalConsoleError;
  }
}

test('saveTerm upserts an existing canonical term by number when the editor submits without term_id', async () => {
  const store = createTermStore([
    { id: 11, group_id: 5, term_number: 1, title: 'Term 1', start_date: null, weeks_count: 15, is_active: true, is_archived: false },
    { id: 12, group_id: 5, term_number: 2, title: 'Custom Term 2', start_date: '2026-09-01', weeks_count: 15, is_active: false, is_archived: false },
    { id: 13, group_id: 5, term_number: 3, title: 'Term 3', start_date: null, weeks_count: 7, is_active: false, is_archived: false },
  ]);

  const result = await withMutedProjectionErrors(() => academicV2Helpers.saveTerm(store, {
    group_id: 5,
    term_number: 2,
    title: '',
    start_date: '',
    is_active: ['0', '1'],
    is_archived: '0',
  }));

  const term1 = store.state.terms.find((row) => Number(row.id || 0) === 11);
  const term2 = store.state.terms.find((row) => Number(row.id || 0) === 12);

  assert.equal(result.row.id, 12);
  assert.equal(store.state.terms.length, 3);
  assert.equal(term1.is_active, false);
  assert.equal(term2.is_active, true);
  assert.equal(term2.title, 'Custom Term 2');
  assert.equal(term2.start_date, '2026-09-01');
});

test('saveTerm still blocks duplicate term numbers when editing a different existing term by id', async () => {
  const store = createTermStore([
    { id: 11, group_id: 5, term_number: 1, title: 'Term 1', start_date: null, weeks_count: 15, is_active: true, is_archived: false },
    { id: 12, group_id: 5, term_number: 2, title: 'Term 2', start_date: null, weeks_count: 15, is_active: false, is_archived: false },
    { id: 13, group_id: 5, term_number: 3, title: 'Term 3', start_date: null, weeks_count: 7, is_active: false, is_archived: false },
  ]);

  await assert.rejects(
    academicV2Helpers.saveTerm(store, {
      term_id: 11,
      group_id: 5,
      term_number: 2,
      title: 'Renamed term',
      start_date: '',
      is_active: '1',
      is_archived: '0',
    }),
    /TERM_NUMBER_ALREADY_EXISTS/
  );
});
