const test = require('node:test');
const assert = require('node:assert/strict');
const { loadStudentScheduleData } = require('../lib/academicV2Students');

function createStore(trackKey) {
  const optoutsByUser = new Map();
  const subjects = [
    { group_subject_id: 10, subject_template_id: 20, legacy_subject_id: 101,
      subject_title: 'Мікроекономіка', group_count: 2, is_required: true },
    { group_subject_id: 11, subject_template_id: 21, legacy_subject_id: 102,
      subject_title: 'Політична психологія', group_count: 1, is_required: false },
  ].map((subject) => ({ ...subject, is_visible: true, is_general: false, default_group: 1 }));
  const selectionRows = [{ subject_id: 101, group_number: 2 }, { subject_id: 102, group_number: 1 }];
  const scheduleRows = [
    { schedule_entry_id: 1, ...subjects[0], activity_type: 'lecture', target_group_numbers: [] },
    { schedule_entry_id: 2, ...subjects[0], activity_type: 'seminar', target_group_numbers: [1] },
    { schedule_entry_id: 3, ...subjects[0], activity_type: 'seminar', target_group_numbers: [2] },
    { schedule_entry_id: 4, ...subjects[1], activity_type: 'lecture', target_group_numbers: [] },
    { schedule_entry_id: 5, ...subjects[1], activity_type: 'seminar', target_group_numbers: [1] },
  ].map((row) => ({ ...row, group_subject_activity_id: row.schedule_entry_id,
    day_of_week: 'Wednesday', class_number: row.schedule_entry_id, week_number: 1, group_number: 1 }));
  const store = {
    async get(sql) {
      if (sql.includes('FROM academic_v2_groups g')) return {
        group_id: 1, program_id: 1, stage_number: 2, campus_key: 'kyiv',
        legacy_course_id: 110, track_key: trackKey,
      };
      throw new Error(`Unexpected get: ${sql}`);
    },
    async all(sql, params) {
      if (sql.includes('FROM academic_v2_terms')) return [{ id: 1, term_number: 1,
        start_date: '2026-09-01', weeks_count: 15, is_active: true, legacy_semester_id: 1 }];
      if (sql.includes('FROM academic_v2_program_stage_subject_templates')) {
        return subjects.map((subject) => ({ ...subject, term_numbers: [1] }));
      }
      if (sql.includes('FROM academic_v2_group_subjects gs')) return subjects;
      if (sql.includes('FROM student_groups')) return selectionRows;
      if (sql.includes('FROM user_subject_optouts')) {
        return (optoutsByUser.get(params[0]) || []).map((subject_id) => ({ subject_id }));
      }
      if (sql.includes('FROM academic_v2_schedule_entries se')) return scheduleRows;
      throw new Error(`Unexpected all: ${sql}`);
    },
  };
  return { store, optoutsByUser };
}

for (const trackKey of ['bachelor', 'master']) {
  test(`${trackKey}: opting out removes every lesson immediately and choosing again restores them`, async () => {
    const { store, optoutsByUser } = createStore(trackKey);
    const user = { id: 1, group_id: 1, course_id: 110 };
    const load = (person = user) => loadStudentScheduleData(store, person, { weekNumber: 1, debug: true });
    const ids = (state) => state.scheduleRows.map((row) => row.schedule_entry_id);

    assert.deepEqual(ids(await load()), [1, 3, 4, 5]);
    // An explicit opt-out wins even if an old group selection remains stored.
    optoutsByUser.set(user.id, [102]);
    const afterOptout = await load();
    assert.equal(afterOptout.allSubjects.find((subject) => subject.subject_id === 102).opted_out, true);
    assert.deepEqual(ids(afterOptout), [1, 3]);
    assert.ok(afterOptout.debug.row_decisions.filter((row) => row.legacy_subject_id === 102)
      .every((row) => !row.included && row.reason_code === 'dropped_subject_opted_out'));
    // The same course's other student still attends the optional subject.
    assert.deepEqual(ids(await load({ ...user, id: 2 })), [1, 3, 4, 5]);

    optoutsByUser.delete(user.id);
    assert.deepEqual(ids(await load()), [1, 3, 4, 5]);
  });
}
