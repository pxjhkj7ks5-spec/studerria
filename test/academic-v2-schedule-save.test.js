const test = require('node:test');
const assert = require('node:assert/strict');

const academicV2Helpers = require('../lib/academicV2');

function compactSql(sql) {
  return String(sql || '').replace(/\s+/g, ' ').trim();
}

function createScheduleStore(initialEntries = []) {
  const state = {
    nextId: 100,
    deletedIds: [],
    entries: initialEntries.map((row) => ({
      id: Number(row.id || 0),
      group_subject_id: Number(row.group_subject_id || 10),
      group_subject_activity_id: Number(row.group_subject_activity_id || 20),
      term_id: Number(row.term_id || 30),
      group_number: Number(row.group_number || 1),
      target_group_numbers: Array.isArray(row.target_group_numbers) ? row.target_group_numbers : [],
      day_of_week: row.day_of_week || 'Monday',
      class_number: Number(row.class_number || 1),
      week_number: Number(row.week_number || 1),
      lesson_type: row.lesson_type || 'lecture',
    })),
  };

  const tx = {
    get: async (sql, params = []) => {
      const query = compactSql(sql);

      if (
        query.includes('FROM academic_v2_group_subject_activities activity')
        && query.includes('WHERE activity.id = ?')
      ) {
        return {
          id: Number(params[0] || 20),
          group_subject_id: 10,
          activity_type: 'lecture',
          subject_template_id: 40,
          group_id: 50,
          group_count: 1,
          default_group: 1,
          stage_number: 1,
          program_id: 60,
          track_key: 'bachelor',
          stage_subject_template_id: 70,
          stage_group_count: 1,
          stage_default_group: 1,
        };
      }

      if (query.includes('FROM academic_v2_terms') && query.includes('WHERE id = ?')) {
        return { id: Number(params[0] || 30), group_id: 50 };
      }

      if (
        query.includes('SELECT id, target_group_numbers')
        && query.includes('FROM academic_v2_schedule_entries')
        && query.includes('AND week_number = ?')
      ) {
        const [activityId, termId, dayOfWeek, classNumber, weekNumber, groupNumber] = params.map((value) => (
          typeof value === 'string' ? value : Number(value || 0)
        ));
        return state.entries.find((entry) => (
          Number(entry.group_subject_activity_id) === Number(activityId)
          && Number(entry.term_id) === Number(termId)
          && String(entry.day_of_week) === String(dayOfWeek)
          && Number(entry.class_number) === Number(classNumber)
          && Number(entry.week_number) === Number(weekNumber)
          && Number(entry.group_number) === Number(groupNumber)
        )) || null;
      }

      if (
        query.includes('INSERT INTO academic_v2_schedule_entries')
        && query.includes('RETURNING *')
      ) {
        const row = {
          id: state.nextId,
          group_subject_id: Number(params[0] || 0),
          group_subject_activity_id: Number(params[1] || 0),
          term_id: Number(params[2] || 0),
          group_number: Number(params[3] || 0),
          target_group_numbers: Array.isArray(params[4]) ? params[4] : [],
          day_of_week: params[5],
          class_number: Number(params[6] || 0),
          week_number: Number(params[7] || 0),
          lesson_type: params[8],
        };
        state.nextId += 1;
        state.entries.push(row);
        return { ...row };
      }

      throw new Error(`Unexpected get query: ${query}`);
    },
    all: async (sql, params = []) => {
      const query = compactSql(sql);
      if (
        query.includes('SELECT id, target_group_numbers')
        && query.includes('FROM academic_v2_schedule_entries')
        && query.includes('AND week_number = ?')
      ) {
        const [activityId, termId, dayOfWeek, classNumber, weekNumber, groupNumber] = params.map((value) => (
          typeof value === 'string' ? value : Number(value || 0)
        ));
        return state.entries
          .filter((entry) => (
            Number(entry.group_subject_activity_id) === Number(activityId)
            && Number(entry.term_id) === Number(termId)
            && String(entry.day_of_week) === String(dayOfWeek)
            && Number(entry.class_number) === Number(classNumber)
            && Number(entry.week_number) === Number(weekNumber)
            && Number(entry.group_number) === Number(groupNumber)
          ))
          .map((entry) => ({
            id: entry.id,
            target_group_numbers: entry.target_group_numbers,
          }));
      }
      if (
        query.includes('SELECT id, week_number, target_group_numbers')
        && query.includes('FROM academic_v2_schedule_entries')
      ) {
        const [activityId, termId, dayOfWeek, classNumber, groupNumber] = params.map((value) => (
          typeof value === 'string' ? value : Number(value || 0)
        ));
        return state.entries
          .filter((entry) => (
            Number(entry.group_subject_activity_id) === Number(activityId)
            && Number(entry.term_id) === Number(termId)
            && String(entry.day_of_week) === String(dayOfWeek)
            && Number(entry.class_number) === Number(classNumber)
            && Number(entry.group_number) === Number(groupNumber)
          ))
          .map((entry) => ({
            id: entry.id,
            week_number: entry.week_number,
            target_group_numbers: entry.target_group_numbers,
          }));
      }
      throw new Error(`Unexpected all query: ${query}`);
    },
    run: async (sql, params = []) => {
      const query = compactSql(sql);
      if (query.includes('DELETE FROM academic_v2_schedule_entries WHERE id = ?')) {
        const id = Number(params[0] || 0);
        state.deletedIds.push(id);
        state.entries = state.entries.filter((entry) => Number(entry.id) !== id);
        return;
      }
      if (query.includes('DELETE FROM schedule_entries WHERE id = ?')) {
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

test('saveScheduleEntry appends a new week without deleting existing weeks for the same slot', async () => {
  const store = createScheduleStore([
    {
      id: 7,
      group_subject_id: 10,
      group_subject_activity_id: 20,
      term_id: 30,
      group_number: 1,
      target_group_numbers: [],
      day_of_week: 'Monday',
      class_number: 3,
      week_number: 2,
      lesson_type: 'lecture',
    },
  ]);

  await withMutedProjectionErrors(() => academicV2Helpers.saveScheduleEntry(store, {
    group_subject_activity_id: 20,
    term_id: 30,
    day_of_week: 'Monday',
    class_number: 3,
    week_number: 3,
    group_number: 1,
    target_group_numbers: [],
  }));

  assert.deepEqual(store.state.deletedIds, []);
  assert.deepEqual(
    store.state.entries.map((entry) => entry.week_number).sort((left, right) => left - right),
    [2, 3]
  );
});

test('saveScheduleEntry appends a new day without deleting an existing day for the same activity', async () => {
  const store = createScheduleStore([
    {
      id: 7,
      group_subject_id: 10,
      group_subject_activity_id: 20,
      term_id: 30,
      group_number: 1,
      target_group_numbers: [],
      day_of_week: 'Monday',
      class_number: 3,
      week_number: 2,
      lesson_type: 'lecture',
    },
  ]);

  await withMutedProjectionErrors(() => academicV2Helpers.saveScheduleEntry(store, {
    group_subject_activity_id: 20,
    term_id: 30,
    day_of_week: 'Wednesday',
    class_number: 3,
    week_number: 2,
    group_number: 1,
    target_group_numbers: [],
  }));

  assert.deepEqual(store.state.deletedIds, []);
  assert.deepEqual(
    store.state.entries.map((entry) => `${entry.day_of_week}:${entry.week_number}`).sort(),
    ['Monday:2', 'Wednesday:2']
  );
});
