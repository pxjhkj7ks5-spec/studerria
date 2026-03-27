const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildAdmissionCampusChoicesFromCourses,
  buildCatalogAssignmentModeSummary,
  buildCatalogBindingSummary,
  buildRegistrationExperienceSummary,
  buildPathwayReadinessSummary,
  buildRegistrationReadinessAlert,
  buildSubjectVisibilityCopy,
  describeCatalogBinding,
} = require('../lib/pathways');
const {
  buildFailedPromotionTargetIssue,
  buildRegistrationCourseFallbackIssue,
  countLegacyMessageRecipients,
  countLegacySubjectStudents,
  getLegacyCourseActiveSemester,
  getLegacyCourseDependencyCounts,
  getLegacyCourseSubject,
  getLegacyStudentSubjectGroup,
  listLegacyCourseStudentGroupAssignments,
  listLegacyStudentGroupRows,
  listLegacySubjectStudentRows,
  listLegacyCourseUsers,
  listLegacyAdmissionIdsForSubjectIds,
  listLegacyAdmissionCourseRows,
  listLegacyAdmissionSubjectVisibilityRows,
  resolveAdminAcademicScopeState,
  upsertLegacyAdmissionCourseMappings,
} = require('../lib/academicSetup');

test('pathway readiness becomes blocked without mapped courses', () => {
  const summary = buildPathwayReadinessSummary({
    mappedCourses: 0,
    visibleSubjects: 2,
    totalSubjects: 2,
    campusBindings: 1,
  });
  assert.equal(summary.status, 'blocked');
  assert.ok(summary.issues.includes('course_mapping'));
});

test('registration experience summary explains empty subject picker state', () => {
  const summary = buildPathwayReadinessSummary({
    mappedCourses: 1,
    visibleSubjects: 0,
    totalSubjects: 4,
    campusBindings: 1,
  });
  const experience = buildRegistrationExperienceSummary({
    summary,
    lang: 'en',
    mappedCourses: 1,
    visibleSubjects: 0,
    totalSubjects: 4,
    campusBindings: 1,
  });
  assert.equal(experience.tone, 'danger');
  assert.match(experience.title, /empty subject picker/i);
  assert.equal(experience.stages[1].state, 'blocked');
});

test('catalog binding summary counts shared and unassigned entries', () => {
  const summary = buildCatalogBindingSummary({
    lang: 'en',
    entries: [
      {
        id: 1,
        instances: [
          { is_shared: true, course_count: 3, is_visible: true },
          { is_shared: false, course_count: 1, is_visible: true },
        ],
      },
      {
        id: 2,
        instances: [],
      },
    ],
  });
  assert.equal(summary.metrics.shared_instances, 1);
  assert.equal(summary.metrics.separate_instances, 1);
  assert.equal(summary.metrics.unassigned_entries, 1);
  assert.match(summary.body, /not assigned to any course/i);
});

test('subject visibility copy explains partial visibility', () => {
  assert.match(buildSubjectVisibilityCopy({ visibleSubjects: 2, totalSubjects: 5 }), /2/);
});

test('catalog binding description distinguishes shared subjects', () => {
  assert.equal(
    describeCatalogBinding({ isShared: true, bindingCount: 3 }),
    'Shared catalog subject linked to 3 courses'
  );
});

test('registration readiness alert explains blocked mapping state', () => {
  const summary = buildPathwayReadinessSummary({
    mappedCourses: 0,
    visibleSubjects: 2,
    totalSubjects: 4,
    campusBindings: 0,
  });
  const alert = buildRegistrationReadinessAlert({
    summary,
    mappedCourses: 0,
    visibleSubjects: 2,
    totalSubjects: 4,
    campusBindings: 0,
  });
  assert.equal(alert.status, 'blocked');
  assert.match(alert.title, /mapping|мап/i);
});

test('admission campus choices mark ambiguous campuses and filter teacher track', () => {
  const choices = buildAdmissionCampusChoicesFromCourses([
    { id: 1, name: 'Course A', location: 'kyiv', is_teacher_course: 0 },
    { id: 2, name: 'Course B', location: 'kyiv', is_teacher_course: 0 },
    { id: 3, name: 'Teacher Course', location: 'munich', is_teacher_course: 1 },
  ], 'bachelor');
  assert.equal(choices.length, 1);
  assert.equal(choices[0].campus_key, 'kyiv');
  assert.equal(choices[0].is_ambiguous, true);

  const teacherChoices = buildAdmissionCampusChoicesFromCourses([
    { id: 3, name: 'Teacher Course', location: 'munich', is_teacher_course: 1 },
  ], 'teacher');
  assert.equal(teacherChoices[0].campus_key, 'munich');
  assert.equal(teacherChoices[0].is_ambiguous, false);
});

test('catalog assignment mode summary explains shared course propagation', () => {
  const summary = buildCatalogAssignmentModeSummary({
    sharedSubject: true,
    targetCourseCount: 3,
    lang: 'en',
  });
  assert.match(summary, /shared subject instance/i);
  assert.match(summary, /3 selected courses/i);
});

test('admin academic scope resolves explicit study context into derived course scope', () => {
  const state = resolveAdminAcademicScopeState({
    courses: [
      { id: 11, name: 'Course 1' },
      { id: 22, name: 'Course 2' },
    ],
    studyContexts: [
      {
        id: 77,
        course_id: 22,
        program_id: 9,
        admission_id: 15,
        admission_year: 2025,
        stage_number: 2,
        track_key: 'master',
        campus_key: 'munich',
        program_name: 'Public Leadership',
        program_code: 'PL',
      },
    ],
    requestedScope: {
      study_context_id: 77,
    },
    buildStudyContextLabel: (context) => `ctx:${context.id}`,
  });

  assert.equal(state.studyContextId, 77);
  assert.equal(state.courseId, 22);
  assert.equal(state.programId, 9);
  assert.equal(state.admissionId, 15);
  assert.equal(state.stage, 2);
  assert.equal(state.track, 'master');
  assert.equal(state.campus, 'munich');
});

test('registration fallback moderation issue keeps canonical payload contract', () => {
  const issue = buildRegistrationCourseFallbackIssue({
    userId: 4,
    programId: 10,
    admissionId: 25,
    trackKey: 'bachelor',
    campusKey: 'kyiv',
    stageNumber: 1,
    courseId: 3,
    studyContextId: null,
    fallbackSource: 'legacy_course_input',
  });

  assert.equal(issue.issueCode, 'registration_course_fallback');
  assert.match(issue.dedupeKey, /registration-course-fallback/);
  assert.equal(issue.payload.user_id, 4);
  assert.equal(issue.payload.program_id, 10);
  assert.equal(issue.payload.admission_id, 25);
  assert.equal(issue.payload.course_id, 3);
  assert.equal(issue.payload.study_context_id, null);
  assert.equal(issue.payload.fallback_source, 'legacy_course_input');
});

test('failed promotion moderation issue distinguishes missing placement case', () => {
  const issue = buildFailedPromotionTargetIssue({
    userId: 8,
    admissionId: 31,
    programId: 6,
    trackKey: 'master',
    courseId: 4,
    studyContextId: null,
    missingPlacement: true,
  });

  assert.equal(issue.issueCode, 'failed_promotion_target');
  assert.match(issue.title, /without canonical study context/i);
  assert.match(issue.dedupeKey, /missing-placement/);
  assert.equal(issue.payload.user_id, 8);
  assert.equal(issue.payload.admission_id, 31);
  assert.equal(issue.payload.program_id, 6);
});

test('legacy admission course rows helper applies scope filters through service layer', async () => {
  const calls = [];
  const store = {
    async all(sql, params) {
      calls.push({ sql: String(sql), params });
      return [{ admission_id: 8, course_id: 14, is_visible: true }];
    },
  };

  const rows = await listLegacyAdmissionCourseRows(store, {
    admissionId: 8,
    courseId: 14,
    programId: 3,
    trackKey: 'master',
    visibleOnly: true,
    activeOnly: true,
  });

  assert.equal(rows.length, 1);
  assert.match(calls[0].sql, /pac\.admission_id = \?/i);
  assert.match(calls[0].sql, /pac\.course_id = \?/i);
  assert.match(calls[0].sql, /pac\.is_visible = true/i);
  assert.deepEqual(calls[0].params, [8, 3, 14, 'master']);
});

test('legacy admission subject visibility helper supports scoped admission arrays', async () => {
  const calls = [];
  const store = {
    async all(sql, params) {
      calls.push({ sql: String(sql), params });
      return [{ admission_id: 11, subject_id: 22, is_visible: true }];
    },
  };

  const rows = await listLegacyAdmissionSubjectVisibilityRows(store, {
    admissionIds: [11, 12],
    courseId: 5,
    subjectId: 22,
  });

  assert.equal(rows.length, 1);
  assert.match(calls[0].sql, /sva\.admission_id = ANY/i);
  assert.match(calls[0].sql, /scb\.course_id = \?/i);
  assert.match(calls[0].sql, /sva\.subject_id = \?/i);
  assert.deepEqual(calls[0].params, [[11, 12], 5, 22]);
});

test('legacy student group helper uses course bindings when available', async () => {
  const calls = [];
  const store = {
    async all(sql, params) {
      calls.push({ sql: String(sql), params });
      return [{ student_id: 6, subject_id: 14, group_number: 2 }];
    },
  };

  const rows = await listLegacyStudentGroupRows(store, {
    studentId: 6,
    courseId: 9,
  });

  assert.equal(rows.length, 1);
  assert.match(calls[0].sql, /JOIN subject_course_bindings scb/i);
  assert.match(calls[0].sql, /scb\.course_id = \?/i);
  assert.deepEqual(calls[0].params, [6, 9]);
});

test('legacy student group helper falls back to subject owner course on compatibility error', async () => {
  const calls = [];
  let attempt = 0;
  const store = {
    async all(sql, params) {
      calls.push({ sql: String(sql), params });
      attempt += 1;
      if (attempt === 1) {
        const err = new Error('missing binding table');
        err.code = '42P01';
        throw err;
      }
      return [{ student_id: 7, subject_id: 18, group_number: 1 }];
    },
  };

  const rows = await listLegacyStudentGroupRows(store, {
    studentId: 7,
    courseId: 11,
  });

  assert.equal(rows.length, 1);
  assert.equal(calls.length, 2);
  assert.match(calls[1].sql, /s\.course_id = \?/i);
  assert.deepEqual(calls[1].params, [7, 11]);
});

test('legacy subject student helper normalizes course, group, and user filters', async () => {
  const calls = [];
  const store = {
    async all(sql, params) {
      calls.push({ sql: String(sql), params });
      return [{ id: 5, full_name: 'Student', group_number: 2 }];
    },
  };

  const rows = await listLegacySubjectStudentRows(store, {
    subjectId: 12,
    courseId: 3,
    groupNumbers: [2, 2, 'bad'],
    userIds: [5, 5, 'oops'],
    activeOnly: true,
  });

  assert.equal(rows.length, 1);
  assert.match(calls[0].sql, /u\.course_id = \?/i);
  assert.match(calls[0].sql, /sg\.group_number = ANY/i);
  assert.match(calls[0].sql, /u\.id = ANY/i);
  assert.match(calls[0].sql, /u\.is_active/i);
  assert.deepEqual(calls[0].params, [12, 3, [2], [5]]);
});

test('legacy student subject group helper supports active-user filter through facade', async () => {
  const calls = [];
  const store = {
    async get(sql, params) {
      calls.push({ sql: String(sql), params });
      return { group_number: 4 };
    },
  };

  const row = await getLegacyStudentSubjectGroup(store, {
    subjectId: 15,
    studentId: 19,
    activeOnly: true,
  });

  assert.equal(row.group_number, 4);
  assert.match(calls[0].sql, /u\.is_active/i);
  assert.deepEqual(calls[0].params, [15, 19]);
});

test('legacy course student group assignments use bindings when available', async () => {
  const calls = [];
  const store = {
    async all(sql, params) {
      calls.push({ sql: String(sql), params });
      return [{ student_id: 4, subject_id: 9, group_number: 2 }];
    },
  };

  const rows = await listLegacyCourseStudentGroupAssignments(store, {
    courseId: 7,
    studentIds: [4, 5],
    subjectIds: [9],
    includeSubjectNames: true,
    activeOnly: true,
  });

  assert.equal(rows.length, 1);
  assert.match(calls[0].sql, /JOIN subject_course_bindings scb/i);
  assert.match(calls[0].sql, /scb\.course_id = \?/i);
  assert.match(calls[0].sql, /sg\.student_id = ANY/i);
  assert.match(calls[0].sql, /sg\.subject_id = ANY/i);
  assert.match(calls[0].sql, /u\.is_active/i);
  assert.deepEqual(calls[0].params, [7, [4, 5], [9]]);
});

test('legacy course student group assignments fall back to subject owner course on compatibility error', async () => {
  const calls = [];
  let attempt = 0;
  const store = {
    async all(sql, params) {
      calls.push({ sql: String(sql), params });
      attempt += 1;
      if (attempt === 1) {
        const err = new Error('missing bindings');
        err.code = '42703';
        throw err;
      }
      return [{ student_id: 8, subject_id: 13, group_number: 1 }];
    },
  };

  const rows = await listLegacyCourseStudentGroupAssignments(store, {
    courseId: 11,
    includeSubjectNames: false,
  });

  assert.equal(rows.length, 1);
  assert.equal(calls.length, 2);
  assert.match(calls[1].sql, /s\.course_id = \?/i);
  assert.match(calls[1].sql, /NULL AS subject_name/i);
  assert.deepEqual(calls[1].params, [11]);
});

test('legacy subject student counts aggregate distinct students through service layer', async () => {
  const calls = [];
  const store = {
    async all(sql, params) {
      calls.push({ sql: String(sql), params });
      return [{ subject_id: 12, students_total: 18 }];
    },
  };

  const rows = await countLegacySubjectStudents(store, {
    courseId: 5,
    subjectIds: [12, 13],
    groupNumber: 2,
    activeOnly: true,
  });

  assert.equal(rows.length, 1);
  assert.match(calls[0].sql, /COUNT\(DISTINCT sg\.student_id\)/i);
  assert.match(calls[0].sql, /scb\.course_id = \?/i);
  assert.match(calls[0].sql, /sg\.subject_id = ANY/i);
  assert.match(calls[0].sql, /sg\.group_number = \?/i);
  assert.deepEqual(calls[0].params, [5, [12, 13], 5, 2]);
});

test('legacy message recipient counts batch subject-group targets', async () => {
  const calls = [];
  const store = {
    async all(sql, params) {
      calls.push({ sql: String(sql), params });
      return [{ subject_id: 7, group_number: 1, students_total: 6 }];
    },
  };

  const rows = await countLegacyMessageRecipients(store, {
    courseId: 3,
    targets: [
      { subject_id: 7, group_number: 1 },
      { subject_id: 7, group_number: 1 },
      { subject_id: 8, group_number: 2 },
    ],
    activeOnly: true,
  });

  assert.equal(rows.length, 1);
  assert.match(calls[0].sql, /WITH target_scope/i);
  assert.match(calls[0].sql, /VALUES \(\?, \?\), \(\?, \?\)/i);
  assert.match(calls[0].sql, /COUNT\(DISTINCT u\.id\)/i);
  assert.deepEqual(calls[0].params, [7, 1, 8, 2, 3]);
});

test('legacy admission id helper resolves subject bindings through service layer', async () => {
  const calls = [];
  const store = {
    async all(sql, params) {
      calls.push({ sql: String(sql), params });
      return [{ admission_id: 14 }];
    },
  };

  const rows = await listLegacyAdmissionIdsForSubjectIds(store, [4, '5', 4]);
  assert.equal(rows.length, 1);
  assert.match(calls[0].sql, /JOIN program_admission_courses pac/i);
  assert.deepEqual(calls[0].params, [[4, 5]]);
});

test('legacy admission course upsert helper normalizes mapping writes', async () => {
  const calls = [];
  const store = {
    async run(sql, params) {
      calls.push({ sql: String(sql), params });
      return { rowCount: 1 };
    },
  };

  const writes = await upsertLegacyAdmissionCourseMappings(store, {
    admissionId: 9,
    mappings: [
      { course_id: '11', is_visible: 'true' },
      { course_id: 12, is_visible: 0 },
      { course_id: null, is_visible: true },
    ],
  });

  assert.equal(writes, 2);
  assert.match(calls[0].sql, /INSERT INTO program_admission_courses/i);
  assert.deepEqual(calls[0].params, [9, 11, true]);
  assert.deepEqual(calls[1].params, [9, 12, false]);
});

test('legacy course active semester helper applies active-semester filter', async () => {
  const calls = [];
  const store = {
    async get(sql, params) {
      calls.push({ sql: String(sql), params });
      return { id: 12, title: 'Spring' };
    },
  };

  const row = await getLegacyCourseActiveSemester(store, 9);
  assert.equal(row.id, 12);
  assert.match(calls[0].sql, /FROM semesters/i);
  assert.match(calls[0].sql, /is_active/i);
  assert.deepEqual(calls[0].params, [9]);
});

test('legacy course subject helper falls back to direct subjects table on schema-compat mode', async () => {
  const calls = [];
  const store = {
    async get(sql, params) {
      calls.push({ sql: String(sql), params });
      if (calls.length === 1) {
        const err = new Error('missing bindings');
        err.code = '42P01';
        throw err;
      }
      return { id: 5, course_id: 2, owner_course_id: 2 };
    },
  };

  const row = await getLegacyCourseSubject(store, {
    subjectId: 5,
    courseId: 2,
    includeHidden: true,
  });

  assert.equal(row.id, 5);
  assert.match(calls[0].sql, /subject_course_bindings/i);
  assert.match(calls[1].sql, /FROM subjects/i);
  assert.deepEqual(calls[1].params, [5, 2]);
});

test('legacy course users helper normalizes filters through service layer facade', async () => {
  const calls = [];
  const store = {
    async all(sql, params) {
      calls.push({ sql: String(sql), params });
      return [{ id: 7, role: 'student' }];
    },
  };

  const rows = await listLegacyCourseUsers(store, {
    courseId: 4,
    userIds: [7, '8', 7],
    excludeRoles: ['admin', 'teacher'],
    activeOnly: true,
  });

  assert.equal(rows.length, 1);
  assert.match(calls[0].sql, /u\.course_id = \?/i);
  assert.match(calls[0].sql, /u\.id = ANY/i);
  assert.match(calls[0].sql, /ANY\(\?::text\[\]\)/i);
  assert.match(calls[0].sql, /is_active/i);
  assert.deepEqual(calls[0].params, [4, [7, 8], ['admin', 'teacher']]);
});

test('legacy course dependency counts normalize count aliases', async () => {
  const calls = [];
  const counts = [{ cnt: 3 }, { count: 5 }, { count: 1 }];
  const store = {
    async get(sql, params) {
      calls.push({ sql: String(sql), params });
      return counts.shift();
    },
  };

  const result = await getLegacyCourseDependencyCounts(store, 15);
  assert.deepEqual(result, { users: 3, subjects: 5, semesters: 1 });
  assert.equal(calls.length, 3);
  calls.forEach((call) => assert.deepEqual(call.params, [15]));
});
